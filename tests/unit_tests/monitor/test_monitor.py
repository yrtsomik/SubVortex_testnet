import time
from unittest.mock import patch, Mock
from subnet.monitor.monitor import Monitor


def test_get_monitored_uids_when_no_run_has_been_done_should_return_an_empty_dictionary():
    # Arrange
    monitor = Monitor()

    # Act
    result = monitor.get_monitored_uids()

    # Assert
    assert 0 == len(result)


@patch("requests.get")
def test_run_when_file_can_not_be_rerieved_should_not_update_the_data(mock_get):
    # Arrange
    monitor = Monitor()
    mock_get.return_value.status_code = 404

    previous_data = monitor.get_monitored_uids()
    previous_time = monitor.last_modified

    # Act
    monitor.run()

    # Assert
    result = monitor.get_monitored_uids()
    assert previous_data == result
    assert previous_time == monitor.last_modified


@patch("requests.get")
def test_run_when_file_has_not_been_updated_should_not_update_the_data(mock_get):
    # Arrange
    monitor = Monitor()
    monitor.last_modified = time.time()

    mock_response = Mock()
    mock_response.headers = {"Last-Modified": monitor.last_modified}
    mock_response.status_code = 200
    mock_get.return_value = mock_response

    previous_data = monitor.get_monitored_uids()
    previous_time = monitor.last_modified

    # Act
    monitor.run()

    # Assert
    result = monitor.get_monitored_uids()
    assert previous_data == result
    assert previous_time == monitor.last_modified


@patch("requests.get")
def test_run_when_file_has_not_been_updated_should_not_update_the_data(mock_get):
    # Arrange
    monitor = Monitor()

    mock_response = Mock()
    mock_response.headers = {"Last-Modified": time.time()}
    mock_response.status_code = 200
    mock_response.text = "27\n128\n173\n225"
    mock_get.return_value = mock_response

    previous_time = monitor.last_modified

    # Act
    monitor.run()

    # Assert
    result = monitor.get_monitored_uids()
    assert previous_time != monitor.last_modified
    assert [27, 128, 173, 225] == result
