# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import ANY, AsyncMock, patch

import pytest
from connexion.lifecycle import ConnexionResponse
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.config.models.base import ValidateFilePathMixin

from server_management_api.constants import INSTALLATION_UID_KEY, UPDATE_INFORMATION_KEY
from server_management_api.controllers.test.utils import CustomAffectedItems, get_default_configuration

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        with patch.object(ValidateFilePathMixin, '_validate_file_path', return_value=None):
            default_config = get_default_configuration()
            CentralizedConfig._config = default_config

            import wazuh.rbac.decorators
            from wazuh import manager
            from wazuh.core.manager import query_update_check_service
            from wazuh.tests.util import RBAC_bypasser

            from server_management_api.controllers.manager_controller import check_available_version

            wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@pytest.mark.parametrize(
    'force_query,task_dispatcher_call_count,update_check', ([True, 2, True], [True, 1, False], [False, 1, True])
)
@pytest.mark.asyncio
@patch('server_management_api.controllers.manager_controller.configuration.update_check_is_enabled')
@patch(
    'server_management_api.controllers.manager_controller.TaskDispatcher.execute_function', return_value=AsyncMock()
)
@patch('server_management_api.controllers.manager_controller.TaskDispatcher.__init__', return_value=None)
@patch('server_management_api.controllers.manager_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_check_available_version(
    mock_exc,
    mock_task_dispatcher,
    mock_dfunc,
    update_check_mock,
    force_query,
    task_dispatcher_call_count,
    update_check,
):
    """Verify 'check_available_version' endpoint is working as expected."""
    cti_context = {UPDATE_INFORMATION_KEY: {'foo': 1}, INSTALLATION_UID_KEY: '1234'}
    update_check_mock.return_value = update_check

    with patch('server_management_api.controllers.manager_controller.cti_context', new=cti_context):
        result = await check_available_version(force_query=force_query)
        assert mock_task_dispatcher.call_count == task_dispatcher_call_count

        if force_query and update_check:
            mock_task_dispatcher.assert_any_call(
                f=query_update_check_service,
                f_kwargs={INSTALLATION_UID_KEY: cti_context[INSTALLATION_UID_KEY]},
                        is_async=True,
                logger=ANY,
            )
            mock_exc.assert_any_call(mock_dfunc.return_value)

        mock_task_dispatcher.assert_called_with(
            f=manager.get_update_information,
            f_kwargs={
                INSTALLATION_UID_KEY: cti_context[INSTALLATION_UID_KEY],
                UPDATE_INFORMATION_KEY: cti_context[UPDATE_INFORMATION_KEY],
            },
                is_async=False,
            logger=ANY,
        )
        mock_exc.assert_called_with(mock_dfunc.return_value)
    assert isinstance(result, ConnexionResponse)
