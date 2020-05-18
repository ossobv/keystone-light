keystone-light :: A limited Identity API v3 python client
=========================================================

keystone-light implements a Python interface to a very limited subset of
the `OpenStack Identity API v3`_.

Initial goal: *access to OpenStack Swift, using the Identity API v3, but
with a lot fewer dependencies.*

As of this writing, the ``python-keystoneclient`` requires
``keystoneauth1`` and ``oslo.*``, which in turn require some more. We
only require the *ubiquitous* ``requests`` (and ``PyYAML``), which you
generally already have installed anyway.


Example usage
-------------

.. code-block:: python

    #!/usr/bin/env python3
    from urllib.parse import urljoin

    import requests
    from keystone_light import Cloud, CloudsYamlConfig, PermissionDenied


    def get_projects(cloud):
        "Yields projects, sorted by domain and project name"
        domains = cloud.get_domains()
        for domain in sorted(domains, key=(lambda x: x.name)):
            if domain.name == 'Default':
                # print('WARN: skipping domain Default (fixme?)')
                continue

            projects = domain.get_projects()
            for project in sorted(projects, key=(lambda x: x.name)):
                project.domain = domain
                yield project

    def _give_us_project_perms_through_admin_group(project):
        """
        Make sure we are in the *-admin group. Make sure the *-admin
        group has permissions on the project.
        """
        cloud = project.cloud
        dom_admin_group = project.domain.get_admin_group()

        # First check if we're member of the group at all.
        token = cloud.get_system_token()
        auth_headers = {'X-Auth-Token': str(token)}
        try:
            # FIXME: Undocumented access to system_token!
            user_id = token.data['user']['id']
            assert user_id and isinstance(user_id, str), user_id
        except KeyError:
            raise ValueError('missing user.id?', token.data)

        # Are we in the *-admin group?
        url = urljoin(
            cloud.base_url,
            '/v3/groups/{group_id}/users/{user_id}'.format(
                group_id=dom_admin_group.id, user_id=user_id))
        out = requests.head(url, headers=auth_headers)
        if out.status_code == 404:
            # Add us to the group.
            out = requests.put(url, headers=auth_headers)
            assert out.status_code == 204, (
                'PUT', url, out.status_code, out.text)
            # Double check.
            out = requests.head(url, headers=auth_headers)
        assert out.status_code == 204, (
            'HEAD', url, out.status_code, out.text)

        # Grant *-admin power to the project.
        admin_role = cloud.get_role(name='admin')  # or 'reader'
        url = urljoin(
            cloud.base_url,
            '/v3/projects/{project_id}/groups/{group_id}/roles/{role_id}'.format(
                project_id=project.id, group_id=dom_admin_group.id,
                role_id=admin_role.id))
        out = requests.put(url, headers=auth_headers)
        assert out.status_code in (201, 204), (
            'PUT', url, out.status_code, out.text)

    def get_swift_stat_ensuring_permissions(project):
        "Get Swift v1 stat on a project (previously: tenant)"
        try:
            stat = project.get_swift().get_stat()
        except PermissionDenied:
            # We don't have permission to access the project? Upgrade the
            # permissions and try again.
            _give_us_project_perms_through_admin_group(project)
        else:
            return stat

        # Try again. Should succeed now, with the added permissions.
        try:
            stat = project.get_swift().get_stat()
        except PermissionDenied as e:
            raise MyPermissionDenied(
                'EPERM on {domain}.{project}: {exc} {exc_args}'.format(
                    domain=project.domain.name, project=project.name,
                    exc=e.__class__.__name__, exc_args=e.args)) from e
        else:
            return stat


    # Take config from ~/.config/openstack/clouds.yaml and select
    # 'my-cloud-admin', like the openstack(1) --os-cloud option.
    config = CloudsYamlConfig('my-cloud-admin')
    cloud = Cloud(config)
    for project in get_projects(cloud):
        swift_stat = get_swift_stat_ensuring_permissions(project)
        print('{:15s} {:23s} {:21d} B ({} objects, {} containers)'.format(
            project.domain.name[0:15], project.name,
            int(swift_stat['X-Account-Bytes-Used']),
            swift_stat['X-Account-Object-Count'],
            swift_stat['X-Account-Container-Count']))


Example output
--------------

.. code-block:: console

    $ python3 example.py
    domainx         project                  3489 B (2 objects, 1 containers)
    domainx         otherproject       1455042022 B (267 objects, 1 containers)
    ...


Swift Example usage
-------------------

.. code-block:: python

    from keystone_light import Cloud, DirectConfig

    KEYSTONE_URL = 'https://<DOMAIN>:<USER>:<PASS>@KEYSTONE'
    SWIFT_PROJECT = '<DOMAIN>:<PROJECT>'
    SWIFT_CONTAINER = 'some-container'

    config = DirectConfig(KEYSTONE_URI)
    project = Cloud(config).get_current_project()
    assert project.get_fullname() == SWIFT_PROJECT, project.get_fullname()

    swift = project.get_swift()
    container = swift.get_container(SWIFT_CONTAINER)

    # (Re-)upload file:
    filename = ('bloblet.bin' if False else 'blobzilla.bin')
    with open(filename, 'rb') as fp:
        try:
            container.delete(filename)
        except FileNotFoundError:
            pass
        # TIP: Use ChunkIteratorIOBaseWrapper(fp) if the input file
        # is a pipe/stream.
        container.put(filename, fp)

    # Download file:
    filename2 = '{}.retrieved'.format(filename)
    with container.get(filename) as response, \
            open(filename2, 'wb') as fp:
        for chunk in response.iter_content(chunk_size=8192):
            fp.write(chunk)

    # Check and compare:
    with open(filename, 'rb') as fp, \
            open(filename2, 'rb') as fp2:
        buf = buf2 = True
        while buf and buf2:
            buf = fp.read(8192)
            buf2 = fp2.read(8192)
            assert buf == buf2
        assert buf == buf2

And an example with timing:

.. code-block:: python

    from timeit import timeit

    # ...

    # Download file:
    filename2 = '{}.retrieved'.format(filename)
    def _get():
        with container.get(filename) as response, \
                open(filename2, 'wb') as fp:
            for chunk in response.iter_content(chunk_size=8192):
                fp.write(chunk)
    print('{:7.3f} GET'.format(timeit(number=1, stmt=_get)))


.. _`OpenStack Identity API v3`: https://docs.openstack.org/api-ref/identity/v3/
