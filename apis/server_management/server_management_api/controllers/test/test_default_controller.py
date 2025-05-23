# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import MagicMock, patch

import pytest
from connexion.lifecycle import ConnexionResponse

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        import wazuh.rbac.decorators
        from wazuh.core.utils import get_utc_now
        from wazuh.tests.util import RBAC_bypasser

        from server_management_api.controllers.default_controller import DATE_FORMAT, BasicInfo, default_info, socket

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@pytest.mark.asyncio
@patch('server_management_api.controllers.default_controller.load_api_spec', return_value=MagicMock())
@patch('server_management_api.controllers.default_controller.WazuhResult', return_value={})
async def test_default_info(mock_wresult, mock_lspec):
    """Verify 'default_info' endpoint is working as expected."""
    result = await default_info()
    data = {
        'title': mock_lspec.return_value['info']['title'],
        'api_version': mock_lspec.return_value['info']['version'],
        'revision': mock_lspec.return_value['info']['x-revision'],
        'license_name': mock_lspec.return_value['info']['license']['name'],
        'license_url': mock_lspec.return_value['info']['license']['url'],
        'hostname': socket.gethostname(),
        'timestamp': get_utc_now().strftime(DATE_FORMAT),
    }
    mock_lspec.assert_called_once_with()
    mock_wresult.assert_called_once_with({'data': BasicInfo.from_dict(data)})
    assert isinstance(result, ConnexionResponse)
