#!/usr/bin/env python
from ansible.module_utils.basic import AnsibleModule
import requests
from requests.auth import HTTPDigestAuth


def map_roles(role):
    if type(role) is str:
        return dict(roleName=role, databaseName='admin')
    else:
        return role


def get_user(atlas_group_id, atlas_username, atlas_api_key, user):
    url = "https://cloud.mongodb.com/api/atlas/v1.0/groups/" + atlas_group_id \
        + "/databaseUsers/admin/" + user
    response = requests.get(url, auth=HTTPDigestAuth(atlas_username,
                            atlas_api_key))
    user_json = response.json()
    response.close()
    user_json['url'] = url
    return user_json


def create_user(atlas_group_id, atlas_username, atlas_api_key, user, roles,
                password):
    roles_with_dbs = map(map_roles, roles)
    url = "https://cloud.mongodb.com/api/atlas/v1.0/groups/" + atlas_group_id \
        + "/databaseUsers"
    user = dict(databaseName='admin',
                groupId=atlas_group_id,
                username=user,
                roles=roles_with_dbs,
                password=password)
    response = requests.post(url, json=user,
                             auth=HTTPDigestAuth(atlas_username,
                                                 atlas_api_key))
    post_json = response.json()
    response.close()
    post_json['url'] = url
    return post_json


def delete_user(atlas_group_id, atlas_username, atlas_api_key, user):
    url = "https://cloud.mongodb.com/api/atlas/v1.0/groups/" + atlas_group_id \
        + "/databaseUsers/admin/"+user
    response = requests.delete(url, auth=HTTPDigestAuth(atlas_username,
                                                        atlas_api_key))
    delete_json = response.json()
    response.close()
    delete_json['url'] = url
    return delete_json


def sync_user(atlas_group_id, atlas_username, atlas_api_key, user,
              http_response, roles, password):
    roles_with_dbs = map(map_roles, roles)
    if http_response['roles'] == roles_with_dbs and password is None:
        return dict(changed=False)

    payload = dict(databaseName='admin',
                   groupId=atlas_group_id,
                   username=user,
                   roles=roles_with_dbs)

    if password is not None:
        payload['password'] = password

    url = "https://cloud.mongodb.com/api/atlas/v1.0/groups/" + atlas_group_id \
        + "/databaseUsers/admin/"+user

    response = requests.patch(url, json=payload, auth=HTTPDigestAuth(
                              atlas_username,
                              atlas_api_key))

    patch_json = response.json()
    patch_json['changed'] = True
    response.close()
    patch_json['url'] = url
    return patch_json


def main():
    """Load the option and route the methods to call"""
    module = AnsibleModule(
            argument_spec=dict(
                atlas_username=dict(required=True, type='str'),
                atlas_api_key=dict(required=True, type='str', no_log=True),
                atlas_group_id=dict(required=True, type='str'),
                user=dict(required=True, type='str', no_log=False),
                password=dict(required=False, type='str', no_log=True),
                state=dict(default='present', choices=['absent', 'present']),
                update_password=dict(default='always', choices=['always',
                                     'on_create']),
                roles=dict(default=None, type='list')
                ),
            supports_check_mode=False
            )
    user = module.params['user']
    password = module.params['password']
    atlas_username = module.params['atlas_username']
    atlas_api_key = module.params['atlas_api_key']
    atlas_group_id = module.params['atlas_group_id']
    state = module.params['state']
    update_password = module.params['update_password']
    roles = module.params['roles']

    subject_response = get_user(atlas_group_id, atlas_username, atlas_api_key,
                                user)

    if subject_response.get('error') is None:
        subject_state = 'present'
    elif subject_response.get('error') == 404:
        subject_state = 'absent'
    else:
        module.fail_json(msg=str(subject_response))
        return

    if state == 'present' and subject_state == 'absent':
        response = create_user(atlas_group_id=atlas_group_id,
                               atlas_username=atlas_username,
                               atlas_api_key=atlas_api_key,
                               user=user, roles=roles, password=password)
        if response.get('error') is None:
            module.exit_json(changed=True, user=user)
        else:
            module.fail_json(msg="Failed to create user:\n"+str(response))
        return

    if state == 'absent' and subject_state == 'absent':
        module.exit_json(changed=False, user=user)
        return

    if state == 'absent' and subject_state == 'present':
        response = delete_user(atlas_group_id, atlas_username, atlas_api_key,
                               user)
        if response.get('error') is None:
            module.exit_json(changed=True, user=user)
        else:
            module.fail_json(msg="Failed to delete user:\n"+str(response))
        return

    if state == 'present' and subject_state == 'present':
        if update_password == 'always' and password is not None:
            response = sync_user(atlas_group_id=atlas_group_id,
                                 atlas_username=atlas_username,
                                 atlas_api_key=atlas_api_key,
                                 user=user, http_response=subject_response,
                                 roles=roles,
                                 password=password)
        else:
            response = sync_user(atlas_group_id=atlas_group_id,
                                 atlas_username=atlas_username,
                                 atlas_api_key=atlas_api_key,
                                 roles=roles,
                                 user=user, http_response=subject_response,
                                 password=None)
        if response.get('error') is None:
            module.exit_json(changed=response['changed'], user=user)
        else:
            module.fail_json(msg="Failed to update user:\n"+str(response),
                             subject=subject_response)
        return


if __name__ == '__main__':
    main()
