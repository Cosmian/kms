#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Patch the kube-apiserver static pod manifest to enable KMS encryption.

Adds:
- --encryption-provider-config flag to the apiserver command
- volumeMount for the EncryptionConfiguration
- volumeMount for the KMS plugin Unix socket directory
- corresponding hostPath volumes
"""
import yaml

MANIFEST = '/etc/kubernetes/manifests/kube-apiserver.yaml'

with open(MANIFEST) as f:
    m = yaml.safe_load(f)

for c in m['spec']['containers']:
    if c.get('name') != 'kube-apiserver':
        continue

    cmd = c.setdefault('command', [])
    enc_flag = '--encryption-provider-config=/etc/kubernetes/enc/config.yaml'
    if enc_flag not in cmd:
        cmd.append(enc_flag)

    # Verbose logging to diagnose KMS gRPC connection issues
    v_flag = '--v=4'
    if v_flag not in cmd:
        cmd.append(v_flag)

    mounts = c.setdefault('volumeMounts', [])
    if not any(vm['name'] == 'enc-config' for vm in mounts):
        mounts.append(
            {
                'name': 'enc-config',
                'mountPath': '/etc/kubernetes/enc',
                'readOnly': True,
            }
        )
    if not any(vm['name'] == 'kms-socket' for vm in mounts):
        mounts.append(
            {
                'name': 'kms-socket',
                'mountPath': '/var/run/cosmian-kms-plugin',
                'readOnly': False,
            }
        )

vols = m['spec'].setdefault('volumes', [])
if not any(v['name'] == 'enc-config' for v in vols):
    vols.append(
        {
            'name': 'enc-config',
            'hostPath': {'path': '/etc/kubernetes/enc', 'type': 'DirectoryOrCreate'},
        }
    )
if not any(v['name'] == 'kms-socket' for v in vols):
    vols.append(
        {
            'name': 'kms-socket',
            'hostPath': {
                'path': '/var/run/cosmian-kms-plugin',
                'type': 'DirectoryOrCreate',
            },
        }
    )

with open(MANIFEST, 'w') as f:
    yaml.dump(m, f, default_flow_style=False)

print('kube-apiserver manifest patched')
