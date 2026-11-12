# -*- coding: utf-8 -*-
import json


def common_argument_spec():
    return {
        'kms_url': {'type': 'str', 'default': 'http://localhost:9998'},
        'api_token': {'type': 'str', 'no_log': True},
        'validate_certs': {'type': 'bool', 'default': True},
        'ca_path': {'type': 'path'},
        'client_cert': {'type': 'path'},
        'client_key': {'type': 'path'},
        'timeout': {'type': 'int', 'default': 30},
    }


def require_minimum(module, name, minimum):
    # argument_spec has no "min" option, so bounds are checked here
    value = module.params.get(name)
    if value is not None and value < minimum:
        module.fail_json(msg='{} must be at least {}'.format(name, minimum))


def kmip_node(tag, type_name, value):
    return {'tag': tag, 'type': type_name, 'value': value}


def kmip_structure(tag, children):
    return {'tag': tag, 'value': children}


def kmip_long_integer(value):
    if value < -(1 << 63) or value >= (1 << 63):
        raise ValueError('KMIP LongInteger is outside the signed 64-bit range')
    return '0x{:016X}'.format(value & ((1 << 64) - 1))


def parse_kmip_long_integer(value):
    if isinstance(value, int):
        return value
    if not isinstance(value, str) or not value.startswith('0x'):
        return value
    number = int(value[2:], 16)
    if number >= 1 << 63:
        number -= 1 << 64
    return number


def find_nodes(node, tag):
    if isinstance(node, dict):
        if node.get('tag') == tag:
            yield node
        for value in node.values():
            yield from find_nodes(value, tag)
    elif isinstance(node, list):
        for value in node:
            yield from find_nodes(value, tag)


def find_values(node, tag):
    return [item.get('value') for item in find_nodes(node, tag) if 'value' in item]


def _kmip_error(module, response):
    for result in find_values(response, 'ResultStatus'):
        if result not in ('Success', 0):
            messages = find_values(response, 'ResultMessage')
            module.fail_json(
                msg=messages[0] if messages else 'KMS returned a failed KMIP operation',
                response=response,
            )


def kms_request(module, method, path, body=None):
    from ansible.module_utils.urls import fetch_url

    params = module.params
    require_minimum(module, 'timeout', 1)
    headers = {'Accept': 'application/json'}
    data = None
    if body is not None:
        headers['Content-Type'] = 'application/json'
        data = json.dumps(body)
    if params.get('api_token'):
        headers['Authorization'] = 'Bearer {}'.format(params['api_token'])

    url = params['kms_url'].rstrip('/') + path
    response, info = fetch_url(
        module,
        url,
        data=data,
        headers=headers,
        method=method,
        timeout=params['timeout'],
        ca_path=params.get('ca_path'),
    )
    status = info.get('status', 0)
    if status != 200:
        module.fail_json(
            msg='KMS API request failed',
            status=status,
            response=info.get('msg') or info.get('body'),
        )

    raw = response.read() if response else info.get('body', '')
    if isinstance(raw, bytes):
        raw = raw.decode('utf-8')
    try:
        return json.loads(raw) if raw else None
    except json.JSONDecodeError as error:
        module.fail_json(msg='KMS API returned invalid JSON: {}'.format(error))


def kmip_request(module, operation):
    response = kms_request(module, 'POST', '/kmip/2_1', operation)
    _kmip_error(module, response)
    return response


def kmip_locate(module, attributes):
    response = kmip_request(
        module,
        kmip_structure(
            'Locate',
            [
                kmip_structure('Attributes', attributes),
                kmip_node('MaximumItems', 'Integer', 2),
            ],
        ),
    )
    return find_values(response, 'UniqueIdentifier')


def kmip_destroy(module, object_id):
    return kmip_request(
        module,
        kmip_structure(
            'Destroy',
            [kmip_node('UniqueIdentifier', 'TextString', object_id)],
        ),
    )


def kmip_attribute_map(response):
    attributes = next(find_nodes(response, 'Attributes'), None)
    if not attributes:
        return {}
    return {
        item['tag']: item.get('value')
        for item in attributes.get('value', [])
        if isinstance(item, dict) and 'tag' in item
    }


def kmip_object_name(name):
    return kmip_structure(
        'Name',
        [
            kmip_node('NameValue', 'TextString', name),
            kmip_node('NameType', 'Enumeration', 'UninterpretedTextString'),
        ],
    )


def access_changes(state, current, requested):
    current = {operation.lower() for operation in current}
    requested = {operation.lower() for operation in requested}
    if state == 'present':
        return sorted(requested - current)
    return sorted(requested & current)


def rotation_policy_plan(current, state, interval_seconds, rotate_name, offset_seconds):
    policy_names = ('RotateAutomatic', 'RotateInterval', 'RotateOffset', 'RotateName')
    if state == 'absent' and not any(name in current for name in policy_names):
        return {}, []
    if state == 'present':
        desired = {
            'RotateAutomatic': ('Boolean', True),
            'RotateInterval': ('LongInteger', interval_seconds),
            'RotateOffset': ('LongInteger', offset_seconds),
        }
        if rotate_name is not None:
            desired['RotateName'] = ('TextString', rotate_name)
    else:
        desired = {
            'RotateAutomatic': ('Boolean', False),
            'RotateInterval': ('LongInteger', 0),
        }

    changes = []
    for name, (type_name, desired_value) in desired.items():
        existing_value = current.get(name)
        if type_name == 'LongInteger':
            existing_value = parse_kmip_long_integer(existing_value)
        if existing_value != desired_value:
            changes.append((name, type_name, desired_value))
    return desired, changes
