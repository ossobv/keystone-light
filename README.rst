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
    from keystone_light import Cloud, CloudConfig, PermissionDenied


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


    def get_swift_stat_ensuring_permissions(project):
        "Get Swift v1 stat on a project (previously: tenant)"
        try:
            stat = project.get_swift().get_stat()
        except PermissionDenied:
            # We don't have permission to access the project? Upgrade the
            # permissions and try again.
            cloud = project.cloud
            admin_role = cloud.get_role(name='admin')  # or 'reader'
            dom_admin_group = project.domain.get_admin_group()

            url = urljoin(
                cloud.base_url,
                ('/v3/projects/{project_id}/groups/{group_id}/'
                 'roles/{role_id}').format(
                    project_id=project.id, group_id=dom_admin_group.id,
                    role_id=admin_role.id))
            out = requests.put(
                url, headers={'X-Auth-Token': str(cloud.get_system_token())})
            assert out.status_code in (201, 204), (out.status_code, out.text)

            # Try again. Should succeed if the cloud admin user is in the
            # dom_admin_group.
            stat = project.get_swift().get_stat()

        return stat


    # Take config from ~/.config/openstack/clouds.yaml and select
    # 'my-cloud-admin', like the openstack(1) --os-cloud option.
    config = CloudConfig('my-cloud-admin')
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


.. _`OpenStack Identity API v3`: https://docs.openstack.org/api-ref/identity/v3/
