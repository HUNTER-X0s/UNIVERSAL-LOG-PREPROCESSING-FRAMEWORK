import re
import yaml
import json

test_yaml = """apiVersion: audit.k8s.io/v1
kind: Event
level: Metadata
stage: ResponseComplete
verb: create
user: cluster-admin
sourceIP: 192.168.1.15
responseStatus: 201
"""
parsed_yaml = yaml.safe_load(test_yaml)
print("YAML:", parsed_yaml)
