import logging
import os
import sys
import tempfile
import warnings

from contextlib import contextmanager
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from itertools import chain
from subprocess import CalledProcessError
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from yaml import load

log = logging.getLogger('keystone_light')
log.addHandler(logging.NullHandler())

# ======================================================================
# OpenStack Keystone
# ----------------------------------------------------------------------
# cloud = Cloud(CloudsYamlConfig('cloudX'))  # or:
# cloud = Cloud(DirectConfig('https://domain:user:pass@...'))
# ======================================================================


class PermissionDenied(Exception):
    def __init__(self, method, url, status_code, response):
        self.args = (method, url, status_code, response)


class ObjectNotFound(Exception):
    pass


class MultipleObjectsFound(Exception):
    pass


def the_one_entry(list_, type_, params):
    if not list_:
        raise ObjectNotFound(
            'lookup of {} with params {} yielded nothing'.format(
                type_, params))
    if len(list_) > 1:
        raise MultipleObjectsFound(
            'lookup of {} with params {} yielded multiple results: {}'.format(
                type_, params, list_))
    return list_[0]


class CloudsYamlConfig:
    """
    Reads ~/.config/openstack/clouds.yaml and selects one

    Example file contents::

        clouds:
          # v-- this would be the selected os_cloud='my-cloud-admin'
          my-cloud-admin:
            auth:
              auth_url: https://KEYSTONE/
              system_scope: all
              user_domain_name: DOMAIN
              username: USERNAME
              password: PASSWORD
            identity_api_version: 3
            region_name: NL1
    """
    def __init__(self, os_cloud):
        with open(os.path.expanduser('~/.config/openstack/clouds.yaml')) as fp:
            clouds_yaml = load(fp.read())

        self.user_info = clouds_yaml['clouds'][os_cloud]
        assert self.user_info['identity_api_version'] == 3, self.user_info

    def get_auth_url(self):
        return self.user_info['auth']['auth_url']

    def as_user_password(self):
        auth = self.user_info['auth']
        password = {
            'user': {
                'name': auth['username'],
                'domain': {
                    'name': auth['user_domain_name'],
                },
                'password': auth['password'],
            },
        }
        return password

    def __str__(self):
        return str(self.user_info)


class CloudConfig(CloudsYamlConfig):
    """
    Old name for CloudsYamlConfig
    """
    def __init__(self, *args, **kwargs):
        warnings.warn(
            'CloudConfig is deprecated, please use CloudsYamlConfig',
            DeprecationWarning, stacklevel=2)
        super().__init__(*args, **kwargs)


class DirectConfig:
    """
    Direct config, by passing https://<DOMAIN>:<USER>:<PASS>@KEYSTONE
    """
    def __init__(self, auth_url):
        parts = urlsplit(auth_url)
        self._auth_url = urlunsplit((
            parts.scheme,
            ('{}:{}'.format(parts.hostname, parts.port) if parts.port
             else parts.hostname),
            parts.path, parts.query, parts.fragment))

        domain, password = parts.username, parts.password
        assert ':' not in domain, domain
        assert ':' in password, 'expected <domain>:<user>:<pass>'
        self._user_domain_name = domain
        self._username, self._password = password.split(':', 1)

    def get_auth_url(self):
        return self._auth_url

    def as_user_password(self):
        password = {'user': {
            'name': self._username,
            'domain': {'name': self._user_domain_name},
            'password': self._password,
        }}
        return password


class CloudToken:
    def __init__(self, unscoped_token=None, cloud_config=None, scope=None):
        self.unscoped_token = unscoped_token
        self.cloud_config = cloud_config
        self.scope = scope
        self.base_url = None
        self.data = None
        self.expires_at = None
        self.token = None
        self.renew()

    def renew(self):
        if self.unscoped_token:
            assert not self.cloud_config
            base_url = self.unscoped_token.base_url
            post_data = {
                'auth': {
                    'identity': {
                        'methods': ['token'],
                        'token': {
                            'id': str(self.unscoped_token),
                        },
                    },
                },
            }
        elif self.cloud_config:
            assert not self.unscoped_token
            base_url = self.cloud_config.get_auth_url()
            post_data = {
                'auth': {
                    'identity': {
                        'methods': ['password'],
                        'password': self.cloud_config.as_user_password(),
                    },
                },
            }
        else:
            raise TypeError('expect unscoped_token OR cloud_config')

        if self.scope:
            post_data['auth']['scope'] = self.scope

        # Optional "?nocatalog", but then we won't get the catalog,
        # which we need for project endpoints.
        url = urljoin(base_url, '/v3/auth/tokens')
        headers = {}
        if self.unscoped_token:
            headers['X-Auth-Token'] = str(self.unscoped_token)

        out = requests.post(url, json=post_data, headers=headers)
        if out.status_code == 401:
            raise PermissionDenied('POST', url, out.status_code, out.text)
        try:
            assert out.status_code == 201
            out_token = out.headers['X-Subject-Token']
            out_data = out.json()
        except (AssertionError, KeyError):
            # FIXME: auth leak to logging in case of errors.
            log.debug(out)
            log.debug(out.headers)
            log.debug(out.content)
            raise

        self.base_url = base_url
        self.data = out_data.pop('token')
        expires_at = self.data.get('expires_at')
        if expires_at is not None:
            if expires_at.endswith('Z'):
                expires_at = expires_at[:-1] + '+00:00'
            expires_at = datetime.fromisoformat(expires_at)
        self.expires_at = expires_at
        assert not out_data, out_data
        self.token = out_token

    def will_expire_within(self, **kwargs):
        if self.expires_at is not None:
            utcnow = datetime.now(timezone.utc)
            if utcnow + timedelta(**kwargs) > self.expires_at:
                return True
        return False

    def __str__(self):
        if self.will_expire_within(minutes=2):
            log.debug('token will expire at %s, force renew', self.expires_at)
            self.renew()
        return self.token


class Cloud:
    def __init__(self, cloud_config):
        self.base_url = cloud_config.get_auth_url()
        self.cloud_config = cloud_config
        self._unscoped_token = None
        self._system_token = None
        self._domain_tokens = {}
        self._project_tokens = {}
        self._endpoints = {}

        self._domains = {}

    def get_roles(self):
        if not hasattr(self, '_get_roles'):
            system_token = self.get_system_token()
            url = urljoin(self.base_url, '/v3/roles')
            out = requests.get(
                url=url, headers={'X-Auth-Token': str(system_token)})
            self._get_roles = [
                Role.from_keystone(i, cloud=self)
                for i in out.json()['roles']]
        return self._get_roles

    def get_role(self, name=None):
        roles = self.get_roles()
        if name is not None:
            roles = [i for i in roles if i.name == name]
        return the_one_entry(roles, 'role', dict(name=name))

    def get_domains(self):
        """
        Get domains from SYSTEM scope
        """
        if not hasattr(self, '_get_domains'):
            system_token = self.get_system_token()
            url = urljoin(self.base_url, '/v3/domains')
            out = requests.get(
                url=url, headers={'X-Auth-Token': str(system_token)})

            for data in out.json()['domains']:
                if data['id'] not in self._domains:
                    self._domains[data['id']] = Domain.from_keystone(
                        data, cloud=self)

            self._get_domains = self._domains.values()
        return self._get_domains

    def get_domain(self, name=None, domain_id=None):
        """
        Get domains by name or id
        """
        # If we have it in cache, return immediately, or create one if
        # we have all the values.
        if domain_id in self._domains:
            return self._domains[domain_id]
        if name and domain_id:
            ret = Domain(name=name, id=domain_id, enabled=True)
            ret.cloud = self
            self._domains[domain_id] = ret
            return ret

        # Otherwise, fetch the SYSTEM domains and filter by args.
        domains = self.get_domains()
        if name is not None:
            domains = [i for i in domains if i.name == name]
        if domain_id is not None:
            domains = [i for i in domains if i.id == domain_id]
        return the_one_entry(
            domains, 'domain', dict(name=name, domain_id=domain_id))

    def get_groups(self, domain_id=None):
        if not hasattr(self, '_get_groups'):
            system_token = self.get_system_token()
            url = urljoin(self.base_url, '/v3/groups')
            out = requests.get(
                url=url, headers={'X-Auth-Token': str(system_token)})
            groups = [
                Group.from_keystone(i, cloud=self)
                for i in out.json()['groups']]
            groups_by_domain = defaultdict(list)
            for group in groups:
                groups_by_domain[group.domain_id].append(group)
            self._get_groups = groups_by_domain

        if domain_id:
            return self._get_groups[domain_id]
        return list(chain(*self._get_groups.values()))

    def get_group(self, name=None, domain_id=None):
        groups = self.get_groups()
        if name is not None:
            groups = [i for i in groups if i.name == name]
        if domain_id is not None:
            groups = [i for i in groups if i.domain_id == domain_id]
        return the_one_entry(
            groups, 'group', dict(name=name, domain_id=domain_id))

    def get_projects(self, domain_id=None):
        """
        Get projects from SYSTEM scope
        """
        if not hasattr(self, '_get_projects'):
            system_token = self.get_system_token()
            url = urljoin(self.base_url, '/v3/projects')
            out = requests.get(
                url=url, headers={'X-Auth-Token': str(system_token)})
            projects = [
                Project.from_keystone(i, cloud=self)
                for i in out.json()['projects']]
            projects_by_domain = defaultdict(list)
            for project in projects:
                projects_by_domain[project.domain_id].append(project)
            self._get_projects = projects_by_domain

        if domain_id:
            return self._get_projects[domain_id]
        return list(chain(*self._get_projects.values()))

    def get_current_project(self):
        """
        Get CURRENT project that belongs to this user
        """
        if not hasattr(self, '_get_current_project'):
            # We expect this in the unscoped_token.data:
            #   "project": {
            #     "name": "x", "domain": {"name": "x", "id": "abc123"},
            #     "id": "abc123"}
            data = self.get_unscoped_token().data
            keystone_dict = {
                'id': data['project']['id'],
                'name': data['project']['name'],
                'enabled': True,
                'is_domain': data['is_domain'],  # not on project...?
                'domain_id': data['project']['domain']['id'],
            }
            self.get_domain(  # the get_domain() creates on in cache
                name=data['project']['domain']['name'],
                domain_id=data['project']['domain']['id'])
            project = Project.from_keystone(keystone_dict, cloud=self)
            self._get_current_project = project
        return self._get_current_project

    def get_unscoped_token(self):
        if not self._unscoped_token:
            self._unscoped_token = CloudToken(cloud_config=self.cloud_config)
        return self._unscoped_token

    def get_system_token(self):
        if not self._system_token:
            system_scope = {'system': {'all': True}}
            unscoped_token = self.get_unscoped_token()
            self._system_token = CloudToken(
                unscoped_token=unscoped_token, scope=system_scope)

            for catalog_row in self._system_token.data.get('catalog', []):
                type_, name = catalog_row['type'], catalog_row['name']
                self.update_endpoints(
                    (type_, name, 'system', 'all'),
                    catalog_row['endpoints'])

        return self._system_token

    def get_domain_token(self, domain_id):
        if domain_id not in self._domain_tokens:
            domain_scope = {'domain': {'id': domain_id}}
            unscoped_token = self.get_unscoped_token()
            domain_token = CloudToken(
                unscoped_token=unscoped_token, scope=domain_scope)

            for catalog_row in domain_token.data.get('catalog', []):
                type_, name = catalog_row['type'], catalog_row['name']
                self.update_endpoints(
                    (type_, name, 'domain', domain_id),
                    catalog_row['endpoints'])

            self._domain_tokens[domain_id] = domain_token

        return self._domain_tokens[domain_id]

    def get_project_token(self, project_id):
        if project_id not in self._project_tokens:
            project_scope = {'project': {'id': project_id}}
            unscoped_token = self.get_unscoped_token()
            project_token = CloudToken(
                unscoped_token=unscoped_token, scope=project_scope)

            for catalog_row in project_token.data.get('catalog', []):
                type_, name = catalog_row['type'], catalog_row['name']
                self.update_endpoints(
                    (type_, name, 'project', project_id),
                    catalog_row['endpoints'])

            self._project_tokens[project_id] = project_token

        return self._project_tokens[project_id]

    def update_endpoints(self, key, endpoints):
        # endpoints = [{"id": "c3f2..", "interface": "public",
        #  "region_id": "NL1", "url": "https://KEYSTONE/v3/", "region": "NL1"}]
        assert key not in self._endpoints, (key, self._endpoints)
        # print('<endpoints>', key, endpoints)
        self._endpoints[key] = endpoints


class Role:
    @classmethod
    def from_keystone(cls, data, cloud):
        # data = {"id": "7931..", "name": "admin",
        #  "domain_id": None, "description": None, "options": {},
        #  "links": {"self": "http://KEYSTONE/v3/roles/7931.."}}
        ret = cls(
            name=data['name'], id=data['id'], domain_id=data['domain_id'])
        ret.cloud = cloud
        return ret

    def __init__(self, name, id, domain_id):
        self.name = name
        self.id = id
        self.domain_id = domain_id

    def __repr__(self):
        return '<Role({})>'.format(self.name)


class Domain:
    @classmethod
    def from_keystone(cls, data, cloud):
        # data = {"id": "b49d...", "name": "DOMAIN", "description": "",
        #  "enabled": True, "tags": [], "options": {},
        #  "links": {"self": "http://KEYSTONE/v3/domains/b49d..."}}
        ret = cls(name=data['name'], id=data['id'], enabled=data['enabled'])
        ret.cloud = cloud
        return ret

    def __init__(self, name, id, enabled):
        self.name = name
        self.id = id
        self.enabled = enabled

    def get_admin_group(self):
        """
        WARNING: This is a configuration choice. We choose to have an
        admin group named DOMAIN-admins. This group should exist.
        """
        groups = [
            i for i in self.get_groups()
            if i.name == '{}-admins'.format(self.name)]
        if len(groups) != 1:
            raise ValueError(
                'expected a single {o.name}-admins group '
                'in domain {o.name} [domain_id={o.id}]'.format(o=self))
        return groups[0]

    def get_groups(self):
        return self.cloud.get_groups(domain_id=self.id)

    def get_projects(self):
        return self.cloud.get_projects(domain_id=self.id)

    def __repr__(self):
        return '<Domain({})>'.format(self.name)


class Group:
    @classmethod
    def from_keystone(cls, data, cloud):
        # data = {"id": "19d9..", "name": "admins", "domain_id": "default",
        #  "description": "",
        #  "links": {"self": "http://KEYSTONE/v3/groups/19d9..."}}
        ret = cls(
            name=data['name'], id=data['id'], domain_id=data['domain_id'])
        ret.cloud = cloud
        return ret

    def __init__(self, name, id, domain_id):
        self.name = name
        self.id = id
        self.domain_id = domain_id

    def __repr__(self):
        return '<Group({})>'.format(self.name)


class Project:
    @classmethod
    def from_keystone(cls, data, cloud):
        # data = {"id": "d304..", "name": "admin", "domain_id": "default",
        #  "description": "Bootstrap..", "enabled": true,
        #  "parent_id": "default", "is_domain": false, "tags": [],
        #  "options": {},
        #  "links": {"self": "http://KEYSTONE/v3/projects/d304.."}}
        ret = cls(
            name=data['name'], id=data['id'], enabled=data['enabled'],
            domain_id=data['domain_id'])
        ret.cloud = cloud
        return ret

    def __init__(self, name, id, enabled, domain_id):
        self.name = name
        self.id = id
        self.enabled = enabled
        self.domain_id = domain_id

    def __repr__(self):
        return '<Project({})>'.format(self.name)

    def get_fullname(self):
        return '{}:{}'.format(self.get_domain().name, self.name)

    def get_domain(self):
        return self.cloud.get_domain(domain_id=self.domain_id)

    def get_swift(self):
        key = ('object-store', 'swift', 'project', self.id)
        # Getting the project token ensures we get the endpoint in the
        # endpoints dict.
        project_token = self.cloud.get_project_token(self.id)
        del project_token

        endpoints = self.cloud._endpoints[key]  # FIXME: encapsulation!
        endpoints = [i for i in endpoints if i['interface'] == 'public']
        endpoint = the_one_entry(endpoints, 'endpoints', dict())
        return Swift.from_keystone(
            endpoint, project_id=self.id, cloud=self.cloud)


# ======================================================================
# OpenStack Swift
# ----------------------------------------------------------------------
# swift = cloud.get....project().get_swift()
# ======================================================================


class SwiftFileExistsError(FileExistsError):
    def __init__(self, filename, strerror):
        EEXIST = 17
        super().__init__(EEXIST, filename)
        self._strerror = strerror

    def __str__(self):
        return self._strerror


class SwiftFileNotFoundError(FileNotFoundError):
    def __init__(self, filename, strerror):
        ENOENT = 2
        super().__init__(ENOENT, filename)
        self._strerror = strerror

    def __str__(self):
        return self._strerror


class Swift:
    @classmethod
    def from_keystone(cls, data, project_id, cloud):
        # data = {"id": "8888..", "interface": "admin",
        #  "url": "https://SWIFT/v1", "region": "NL1"}
        ret = cls(id=data['id'], url=data['url'], region=data['region'])
        ret.project_id = project_id
        ret.cloud = cloud
        return ret

    def __init__(self, id, url, region):
        self.id = id
        self.url = url
        self.region = region

    def _mkurl(self, *args):
        if args:
            return '{}/{}'.format(self.url, '/'.join(args))
        return self.url

    def _mkhdrs(self, json=False):
        project_token = self.cloud.get_project_token(self.project_id)
        headers = {'X-Auth-Token': str(project_token)}
        if json:
            # text/plain, application/json, application/xml, text/xml
            headers['Accept'] = 'application/json'
        return headers

    def get_stat(self):
        url, hdrs = self._mkurl(), self._mkhdrs()
        out = requests.head(url, headers=hdrs)
        if out.status_code == 403:
            # "We" need to give ourselves permission, if possible.
            raise PermissionDenied('HEAD', url, out.status_code, out.text)
        return out.headers

    def get_containers(self):
        url, hdrs = self._mkurl(), self._mkhdrs(json=True)
        out = requests.get(url, headers=hdrs)
        if out.status_code != 200:
            raise PermissionDenied('GET', url, out.status_code, out.text)
        # headers = {
        #   "Server": "nginx/x.x (Ubuntu)",
        #   "Date": "Sat, 16 May 2020 14:57:27 GMT",
        #   "Content-Type": "application/json; charset=utf-8",
        #   "Content-Length": "2",
        #   "X-Account-Container-Count": "0",
        #   "X-Account-Object-Count": "0",
        #   "X-Account-Bytes-Used": "0",
        #   "X-Timestamp": "1589641047.63424",
        #   "X-Put-Timestamp": "1589641047.63424",
        #   "X-Trans-Id": "tx97..",
        #   "X-Openstack-Request-Id": "tx97.."}
        # out.json() = {
        #   {"name": "logbunny-test", "count": 0, "bytes": 0,
        #    "last_modified": "2020-05-16T15:02:03.684680"}
        return [SwiftContainer.from_list(i, swift=self) for i in out.json()]

    def get_container(self, name):
        ret = SwiftContainer(name=name)
        ret.swift = self
        return ret


class SwiftContainer:
    @classmethod
    def from_list(cls, data, swift):
        # data = {"name": "logbunny-test", "count": 0, "bytes": 0,
        #         "last_modified": "2020-05-16T15:02:03.684680"}
        ret = cls(name=data['name'])
        ret.swift = swift
        return ret

    def __init__(self, name):
        self.name = name

    def _mkurl(self, *args):
        return self.swift._mkurl(self.name, *args)

    def ensure_exists(self):
        """
        Make sure the container exists by creating it if it doesn't.

        Keep in mind that it will be created with "default"
        properties/metadata.
        """
        url, hdrs = self._mkurl(), self.swift._mkhdrs()
        out = requests.head(url, headers=hdrs)
        # 200 = OK, 204 = OK (but has no content)
        # 201 = created, 202 accepted (will be creating shortly)
        if out.status_code in (200, 204):
            pass
        elif out.status_code == 404:
            out = requests.put(url, headers=hdrs)
            assert out.status_code in (201, 202), (url, out.status_code)
            out = requests.head(url, headers=hdrs)
            assert out.status_code in (200, 204), (url, out.status_code)
        else:
            assert False, (url, out.status_code)

    def list(self):
        """
        List all files in the container; returns a list of dicts

        NOTE: This interface will change in the future, as we'll want
        filtering capabilities.

        Example return value:

            [
                {"bytes": 432,
                 "content_type": "application/octet-stream",
                 "hash": "<md5-hash>",
                 "last_modified": "2020-05-16T15:58:02.489890",
                 "name": "README.rst"},
                ...
            ]
        """
        url, hdrs = self._mkurl(), self.swift._mkhdrs(json=True)
        out = requests.get(url, headers=hdrs)
        if out.status_code != 200:
            raise PermissionDenied('GET', url, out.status_code, out.text)
        # headers = {
        #   "Server": "nginx/x.x (Ubuntu)",
        #   "Date": "Sat, 16 May 2020 15:20:45 GMT",
        #   "Content-Type": "application/json; charset=utf-8",
        #   "Content-Length": "2",
        #   "X-Container-Object-Count": "0",
        #   "X-Container-Bytes-Used": "0",
        #   "X-Timestamp": "1589641323.69412",
        #   "Last-Modified": "Sat, 16 May 2020 15:02:04 GMT",
        #   "Accept-Ranges": "bytes",
        #   "X-Storage-Policy": "policy0",
        #   "X-Trans-Id": "txe3a...",
        #   "X-Openstack-Request-Id": "txe3a..."}
        # out.json() = [
        #   {"bytes": 432, "hash": "5a..",
        #    "name": "README.rst", "content_type": "application/octet-stream",
        #    "last_modified": "2020-05-16T15:58:02.489890"}]
        return out.json()

    def delete(self, name):
        """
        DELETE (remove) remote Swift file
        """
        url, hdrs = self._mkurl(name), self.swift._mkhdrs()
        out = requests.delete(url, headers=hdrs)
        if out.status_code == 404:
            raise SwiftFileNotFoundError(
                filename=name,
                strerror='DELETE {} {}'.format(url, out.status_code))
        if out.status_code != 204:
            raise PermissionDenied('DELETE', url, out.status_code, out.text)
        assert out.content == b'', out.content

    def get(self, name):
        """
        GET (read) remote Swift file, returns a requests.Response object

        Example usage:

            with container.get(filename) as response, \
                    open(local_filename, 'wb') as fp:
                for chunk in response.iter_content(chunk_size=8192):
                     fp.write(chunk)

        See: https://requests.readthedocs.io/en/master/api/#requests.Response
        """
        url, hdrs = self._mkurl(name), self.swift._mkhdrs()
        out = requests.get(url, headers=hdrs)
        if out.status_code == 404:
            raise SwiftFileNotFoundError(
                filename=name,
                strerror='GET {} {}'.format(url, out.status_code))
        if out.status_code != 200:
            raise PermissionDenied('GET', url, out.status_code, out.text)
        return out

    def head(self, name):
        """
        HEAD (read) remote Swift file metadata, returns a requests.Response
        object
        """
        url, hdrs = self._mkurl(name), self.swift._mkhdrs()
        out = requests.head(url, headers=hdrs)
        if out.status_code == 404:
            raise SwiftFileNotFoundError(
                filename=name,
                strerror='GET {} {}'.format(url, out.status_code))
        if out.status_code != 200:
            raise PermissionDenied('GET', url, out.status_code, out.text)
        assert out.content == b'', out.content
        return out

    def put(self, name, fp, content_type='application/octet-stream',
            check_exists_before=True, check_exists_after=True):
        """
        PUT (write) remote Swift file

        BEWARE: if you're uploading from a file of unknown size (a
        pipe/stream), you may want to wrap the fp in a
        ChunkIteratorIOBaseWrapper: instead of iterating over lines,
        it will iterate over chunks of data.

        NOTE: Right now, we do a:
        - HEAD check before PUT (to ensure we do not overwrite), and a
        - HEAD check after PUT (to ensure the file was written).
        This may prove to be more overhead than we want, so this might
        change in the future. You can disable this by setting the
        `check_exists_*` arguments to False.
        """
        url, hdrs = self._mkurl(name), self.swift._mkhdrs()
        hdrs['Content-Type'] = content_type

        if check_exists_before:
            out = requests.head(url, headers=hdrs)
            if out.status_code != 404:
                raise SwiftFileExistsError(
                    filename=name,
                    strerror='HEAD before PUT {} {}'.format(
                        url, out.status_code))
            assert out.content == b'', out.content

        out = requests.put(url, headers=hdrs, data=fp)
        if out.status_code != 201:
            raise PermissionDenied('PUT', url, out.status_code, out.text)
        assert out.content == b'', out.content

        if check_exists_after:
            out = requests.head(url, headers=hdrs)
            if out.status_code != 200:
                raise SwiftFileNotFoundError(
                    filename=name,
                    strerror='HEAD after PUT {} {}'.format(
                        url, out.status_code))
            assert out.content == b'', out.content


# ======================================================================
# Request helpers
# ======================================================================


class ChunkIteratorIOBaseWrapper:
    """
    Wrapper around python file objects with a chunked iterator

    Regular file objects (IOBase) have a readline() iterator. This
    wrapper changes the iterator to provide appropriately sized chunks
    instead.

    When an input file size is not known beforehand (for streamed IO),
    the requests http library will iterate over the input file. This
    wrapper makes it a lot more efficient.

    Usage:

        infp = sys.stdin.buffer  # let input be a pipe, instead of a file

        # Slow: as infp is iterated over using readlines()
        requests.put('https://path/to/somewhere', data=infp)

        # Fast: as we get decent sized chunks
        requests.put('https://path/to/somewhere', data=(
            ChunkIteratorIOBaseWrapper(infp))

    See also: wsgiref.util.FileWrapper -- but that one does not forward
    calls to like fileno() and seek().
    """
    BUFSIZ = 256 * 1024

    def __init__(self, fp):
        self.__fp = fp

    def __iter__(self):
        # TODO: check for closed file?
        return self

    def __next__(self):
        buf = self.__fp.read(self.BUFSIZ)
        if buf == b'':
            raise StopIteration()
        return buf

    def __getattr__(self, attr):
        "Get property/method from self.__fp instead"
        return getattr(self.__fp, attr)


class FuncOpen:
    """
    Popen "compatible" subprocess handler to be used in Popen-chains

    Because reading a HTTP stream takes userland code (we cannot
    simply read() from the socket), we spawn a subprocess to read and
    write to an anonymous pipe. (*)

    The other end of the pipe can then be read() as usual.

    Usage:

        def data_get_func(dstfp):
            "Closure, to call container.get(name) and write to dstfp"
            with container.get(name) as response:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        dstfp.write(chunk)

        # Example that loads data from a Swift container and feeds it to
        # md5sum directly:
        with FuncOpen(data_get_func) as pipe1, (
                subprocess.Popen(
                    ["md5sum"], stdin=pipe1.stdout,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)) as pipe2:
            md5out, err = pipe2.communicate()
            assert pipe2.wait() == 0 and err == b''
            void, err = pipe1.communicate()
            assert pipe1.wait() == 0 and void == b'' and err == b'', (
                pipe1.returncode, void, err)

        print(md5out)  # b'<md5-hash>  -<LF>'

    (*) Why? For chunked transfer, the data is intermixed with chunk
    headers. For gzipped data, the data also needs decompression.
    """
    def __init__(self, function, stdout=None):
        if stdout is None:
            # Our pipe, our responsibility to clean up the fd.
            c2pread, c2pwrite = os.pipe()
        else:
            # Someone elses responsibility.
            c2pread, c2pwrite = None, stdout.fileno()
        errread, errwrite = os.pipe()

        pid = os.fork()
        if not pid:
            # This is the child
            handled_fds = (None, c2pread, c2pwrite)
            os.close(errread)
            if c2pread is not None:
                os.close(c2pread)
            if sys.stdin and sys.stdin.fileno() not in handled_fds:
                sys.stdin.close()
            if sys.stdout and sys.stdout.fileno() not in handled_fds:
                sys.stdout.close()
            if sys.stderr.fileno() is not None:
                os.dup2(errwrite, sys.stderr.fileno())
            try:
                # Function is called first after the fork(), so we need
                # not worry about anyone setting CLOEXEC on its newly
                # created FDs.
                with os.fdopen(c2pwrite, 'wb') as dstfp:
                    function(dstfp)
            finally:
                try:
                    os.close(errwrite)
                except Exception:
                    pass
            os._exit(0)

        self.pid = pid
        self.returncode = None
        self._using_pipe = (c2pread is not None)

        if self._using_pipe:
            os.close(c2pwrite)
            self.stdout = os.fdopen(c2pread, 'rb')

        os.close(errwrite)
        self._stderr = errread

    def communicate(self):
        # Behave as much as regular Popen as possible. Note that we
        # don't cope with large amounts of stderr while stdout is still
        # (supposed) to be flowing.
        out = b''
        with os.fdopen(self._stderr, 'rb') as fp:
            err = fp.read()
        self._stderr = None
        self.wait()
        return out, err

    def wait(self):
        if self.returncode is None:
            pid, returncode = os.waitpid(self.pid, 0)
            self.returncode = returncode

        if self._stderr is not None:
            os.close(self._stderr)
            self._stderr = None

        return self.returncode

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        if self._using_pipe:
            self.stdout.close()
        self.wait()


class FuncPipe(FuncOpen):
    """
    FuncOpen as a Pipe where we assert that there was no failure
    """
    def communicate(self):
        out, err = super().communicate()
        assert out in (b'', None), out
        if self.returncode != 0:
            log.debug('(stderr) %s', err.decode('ascii', 'replace'))
            raise CalledProcessError(
                cmd='{} (FuncPipe child)'.format(sys.argv[0]), output=err,
                returncode=self.returncode)
        return (None, err)


class SwiftContainerGetPipe(FuncPipe):
    """
    Get data from a container in a subprocess: self.stdout iterates the data

    Usage:

        with SwiftContainerGetPipe(container, remote_name) as pipe1, (
                subprocess.Popen(
                    ["md5sum"], stdin=pipe1.stdout,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)) as pipe2:
            md5out, err = pipe2.communicate()
            pipe1.communicate()
        print(md5out)  # b'<md5-hash>  -<LF>'
    """
    def __init__(self, container, filename, stdout=None):
        # Call generator enter manually and immediately: any 403/404
        # will get picked up now.
        self._response = response = container.get(filename).__enter__()

        # The container data fetch gets to be done in the subprocess.
        def getter(dstfp):
            for chunk in response.iter_content(chunk_size=8192):
                # In the wild, we have seen one case where an apparently empty
                # write propagated to a process causing the read to be cut
                # short, aborting the reader. Still not entirely sure what
                # happened, because we haven't been able to reproduce. But the
                # addition of this if-condition fixed the problem in both
                # occurrences: don't write empty data. It may cause someone to
                # think there is nothing left.
                if chunk:
                    dstfp.write(chunk)

        super().__init__(function=getter, stdout=stdout)

    def __exit__(self, type, value, traceback):
        self._response.__exit__(type, value, traceback)
        super().__exit__(type, value, traceback)


@contextmanager
def TemporaryUntilClosedFile(filename, mode='wb'):
    """
    NamedTemporaryFile replacement that renames if there is no exception

    If there is an exception inside the context handler, the temporary file is
    deleted. If there is _no_ exception, the temporary file is renamed to the
    target filename.

    Usage:

        with TemporaryUntilClosedFile(local_name) as outfp, \\
                SwiftContainerGetPipe(
                    container, remote_name, outfp) as source:
            source.communicate()
    """
    # Use dir=directory-of-the-file, so we won't have issues with
    # cross-filesystem-moves.
    ret = tempfile.NamedTemporaryFile(
        mode=mode, dir=os.path.dirname(filename), delete=False)
    try:
        yield ret
    except Exception:
        os.unlink(ret.name)
        raise
    else:
        os.rename(ret.name, filename)
