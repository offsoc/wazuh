# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
from contextvars import ContextVar
from grp import getgrnam
from pwd import getpwnam
from unittest.mock import patch

import pytest

from wazuh.core.common import find_wazuh_path, wazuh_uid, wazuh_gid


@pytest.mark.parametrize('fake_path, expected', [
    ('/var/ossec/framework/python/lib/python3.7/site-packages/wazuh-3.10.0-py3.7.egg/wazuh', '/var/ossec'),
    ('/my/custom/path/framework/python/lib/python3.7/site-packages/wazuh-3.10.0-py3.7.egg/wazuh', '/my/custom/path'),
    ('/my/fake/path', '')
])
def test_find_wazuh_path(fake_path, expected):
    with patch('wazuh.core.common.__file__', new=fake_path):
        assert (find_wazuh_path.__wrapped__() == expected)


def test_find_wazuh_path_relative_path():
    with patch('os.path.abspath', return_value='~/framework'):
        assert (find_wazuh_path.__wrapped__() == '~')


def test_wazuh_uid():
    with patch('wazuh.core.common.getpwnam', return_value=getpwnam("root")):
        wazuh_uid()


def test_wazuh_gid():
    with patch('wazuh.core.common.getgrnam', return_value=getgrnam("root")):
        wazuh_gid()


@patch('wazuh.core.logtest.create_wazuh_socket_message', side_effect=SystemExit)
def test_origin_module_context_var_framework(mock_create_socket_msg):
    """Test that the origin_module context variable is being set to framework."""
    from wazuh import logtest

    # side_effect used to avoid mocking the rest of functions
    with pytest.raises(SystemExit):
        logtest.run_logtest()

    assert mock_create_socket_msg.call_args[1]['origin']['module'] == 'framework'


@pytest.mark.asyncio
@patch('wazuh.core.logtest.create_wazuh_socket_message', side_effect=SystemExit)
@patch('wazuh.core.cluster.dapi.dapi.DistributedAPI.check_wazuh_status', side_effect=None)
async def test_origin_module_context_var_api(mock_check_wazuh_status, mock_create_socket_msg):
    """Test that the origin_module context variable is being set to API."""
    import logging
    from wazuh.core.cluster.dapi import dapi
    from wazuh import logtest

    # side_effect used to avoid mocking the rest of functions
    with pytest.raises(SystemExit):
        d = dapi.DistributedAPI(f=logtest.run_logtest, logger=logging.getLogger('wazuh'), is_async=True)
        await d.distribute_function()

    assert mock_create_socket_msg.call_args[1]['origin']['module'] == 'API'
