#!/usr/bin/env python
import requests
from requests.auth import HTTPDigestAuth
import json

def get_user(atlas_group_id, atlas_username, atlas_api_key, user):
    url = "https://cloud.mongodb.com/api/atlas/v1.0/groups/"+atlas_group_id+"/databaseUsers/admin/"+user
    response = requests.get(url, auth=HTTPDigestAuth(atlas_username, atlas_api_key))
    return json.loads(response.text)

def delete_user(atlas_group_id, atlas_username, atlas_api_key, user):
    url = "https://cloud.mongodb.com/api/atlas/v1.0/groups/"+atlas_group_id+"/databaseUsers/admin/"+user
    response = requests.delete(url, auth=HTTPDigestAuth(atlas_username, atlas_api_key))
    return json.loads(response.text)

def sync_user(atlas_group_id, atlas_username, atlas_api_key, user,
        update_password, http_response):
    pass

def main():
    """Load the option and route the methods to call"""
    module = AnsibleModule(
            argument_spec=dict(
                atlas_username=dict(required=True, type='str'),
                atlas_api_key=dict(required=True, type='str', no_log=True),
                atlas_group_id=dict(required=True, type='str'),
                user=dict(required=True, type='str'),
                state=dict(default='present', choices=['absent', 'present']),
                update_password=dict(default='always', choices=['always',
                    'on_create'])
                ),
            supports_check_mode=True
            )
    user = module.params['user']
    atlas_username = modules.params['atlas_username']
    atlas_api_key = module.params['api_key']
    atlas_group_id = module.params['group_id']
    state = module.params['state']
    update_password = module.params['update_password']

    subject_response = get_user(atlas_group_id, atlas_username, atlas_api_key,
            user)

    if subject_response.get('error') == None:
        subject_state = 'present'
    else:
        subject_state = 'absent'

    if state == 'absent' and subject_state == 'absent':
        module.exit_json(changed=False, user=user)
        return

    if state == 'absent' and subject_state == 'present':
        response = delete_user(atlas_group_id, atlas_username, atlas_api_key, user)
        if response.status_code == 200:
            module.exit_json(changed=True, user=user)
        else:
            module.fail_json(msg="Failed to delete user:\n"+response.text)

    if state == 'present' and subject_state == 'present':
        changed = sync_user(atlas_group_id=atlas_group_id,
                atlas_username=atlas_username, atlas_api_key=atlas_api_key,
                user=user, update_password=update_password,
                http_response=subject_response)

from ansible.module_utils.basic import *
if __name__ == '__main__':
    main()
