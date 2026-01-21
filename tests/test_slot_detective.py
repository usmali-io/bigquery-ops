
import sys
import unittest
from unittest.mock import MagicMock, patch

# Mock dotenv before importing agent
sys.modules["dotenv"] = MagicMock()
sys.modules["google"] = MagicMock()
sys.modules["google.auth"] = MagicMock()
sys.modules["google.cloud"] = MagicMock()
sys.modules["google.cloud.bigquery"] = MagicMock()
sys.modules["google.oauth2"] = MagicMock()
sys.modules["google.oauth2.credentials"] = MagicMock()
sys.modules["vertexai"] = MagicMock()
sys.modules["vertexai.generative_models"] = MagicMock()
sys.modules["PIL"] = MagicMock()

from agent import operational_tools

class TestSlotDetective(unittest.TestCase):
    @patch('agent.operational_tools._run_query')
    def test_get_slow_queries(self, mock_run_query):
        mock_run_query.return_value = [{'job_id': '123', 'duration_seconds': 100}]
        result = operational_tools.get_slow_queries(days=7)
        self.assertEqual(len(result), 1)
        self.assertIn("INFORMATION_SCHEMA.JOBS_BY_PROJECT", mock_run_query.call_args[0][0])

    @patch('agent.operational_tools._run_query')
    def test_analyze_data_skew(self, mock_run_query):
        mock_run_query.return_value = [{'diagnosis': 'Data Skew Detected'}]
        result = operational_tools.analyze_data_skew('job_123')
        self.assertEqual(result[0]['diagnosis'], 'Data Skew Detected')
        self.assertIn("job_id = @job_id", mock_run_query.call_args[0][0])

if __name__ == '__main__':
    unittest.main()
