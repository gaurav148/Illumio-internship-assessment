import unittest
import tempfile
import os
from main import LookupTable, LogParser, OutputWriter

class TestFlowLogProcessor(unittest.TestCase):
    def setUp(self):
        # Sample lookup table content
        self.lookup_content = "dstport,protocol,tag\n25,tcp,email\n443,tcp,secure\n23,tcp,management\n"
        
        # Sample flow log content (version 2)
        self.flow_log_content = """2 123 eni-abc 10.0.0.1 192.0.2.1 12345 25 6 10 5000 1620140761 1620140821 ACCEPT OK
2 123 eni-def 10.0.0.2 192.0.2.2 12346 443 6 20 8000 1620140761 1620140821 ACCEPT OK
2 123 eni-ghi 10.0.0.3 192.0.2.3 12347 9999 6 15 6000 1620140761 1620140821 ACCEPT OK
"""

        # Create temporary files for lookup and flow logs
        self.lookup_file = tempfile.NamedTemporaryFile(delete=False, mode='w+')
        self.flow_log_file = tempfile.NamedTemporaryFile(delete=False, mode='w+')
        self.output_file = tempfile.NamedTemporaryFile(delete=False, mode='w+')

        # Write sample data to temporary files
        self.lookup_file.write(self.lookup_content)
        self.lookup_file.close()

        self.flow_log_file.write(self.flow_log_content)
        self.flow_log_file.close()

    def tearDown(self):
        # Cleanup temporary files after each test
        os.unlink(self.lookup_file.name)
        os.unlink(self.flow_log_file.name)
        os.unlink(self.output_file.name)

    # Test 1: Lookup table loading
    def test_lookup_table_loading(self):
        lookup = LookupTable(self.lookup_file.name)
        tag_map = lookup.load_lookup()

        self.assertEqual(tag_map[('25', 'tcp')], 'email')
        self.assertEqual(tag_map[('443', 'tcp')], 'secure')
        self.assertEqual(tag_map[('23', 'tcp')], 'management')

    # Test 2: Processing logs and tag mapping
    def test_flow_log_processing(self):
        lookup = LookupTable(self.lookup_file.name)
        tag_map = lookup.load_lookup()

        parser = LogParser(self.flow_log_file.name, tag_map)
        tag_counts, port_protocol_counts = parser.process_logs()

        self.assertEqual(tag_counts['email'], 1)
        self.assertEqual(tag_counts['secure'], 1)
        self.assertEqual(tag_counts['Untagged'], 1)

        self.assertEqual(port_protocol_counts[('25', 'tcp')], 1)
        self.assertEqual(port_protocol_counts[('443', 'tcp')], 1)
        self.assertNotIn(('9999', 'tcp'), port_protocol_counts)

    # Test 3: Handling empty flow log file
    def test_empty_flow_log(self):
        empty_log_file = tempfile.NamedTemporaryFile(delete=False, mode='w+')
        empty_log_file.close()

        lookup = LookupTable(self.lookup_file.name)
        tag_map = lookup.load_lookup()

        parser = LogParser(empty_log_file.name, tag_map)
        tag_counts, port_protocol_counts = parser.process_logs()

        self.assertEqual(len(tag_counts), 0)
        self.assertEqual(len(port_protocol_counts), 0)

        os.unlink(empty_log_file.name)

    # Test 4: Handling empty lookup table
    def test_empty_lookup_table(self):
        empty_lookup_file = tempfile.NamedTemporaryFile(delete=False, mode='w+')
        empty_lookup_file.close()

        lookup = LookupTable(empty_lookup_file.name)
        tag_map = lookup.load_lookup()

        parser = LogParser(self.flow_log_file.name, tag_map)
        tag_counts, port_protocol_counts = parser.process_logs()

        self.assertEqual(tag_counts['Untagged'], 3)
        self.assertEqual(len(port_protocol_counts), 0)

        os.unlink(empty_lookup_file.name)

    # Test 5: Invalid log lines (malformed data)
    def test_invalid_log_lines(self):
        # Taking input of 3 rows, 1 valid and 2 invalid
        invalid_log_content = """2 123 eni-abc 10.0.0.1 192.0.2.1 12345 25 6 ACCEPT OK
2 123 eni-def 10.0.0.2 192.0.2.2 12346 443 6 20 8000 1620140761 1620140821 ACCEPT OK
invalid line without proper format
"""

        invalid_log_file = tempfile.NamedTemporaryFile(delete=False, mode='w+')
        invalid_log_file.write(invalid_log_content)
        invalid_log_file.close()

        lookup = LookupTable(self.lookup_file.name)
        tag_map = lookup.load_lookup()

        parser = LogParser(invalid_log_file.name, tag_map)
        tag_counts, port_protocol_counts = parser.process_logs()

        self.assertEqual(tag_counts['secure'], 1) # The 1 valid row is tagged properly
        self.assertEqual(tag_counts['Untagged'], 0)  # Only valid lines are processed

        os.unlink(invalid_log_file.name)

    # Test 6: Duplicate entries in lookup table
    def test_duplicate_lookup_entries(self):
        duplicate_lookup_content = "dstport,protocol,tag\n25,tcp,email\n25,tcp,overwritten\n"
        duplicate_lookup_file = tempfile.NamedTemporaryFile(delete=False, mode='w+')
        duplicate_lookup_file.write(duplicate_lookup_content)
        duplicate_lookup_file.close()

        lookup = LookupTable(duplicate_lookup_file.name)
        tag_map = lookup.load_lookup()

        parser = LogParser(self.flow_log_file.name, tag_map)
        tag_counts, port_protocol_counts = parser.process_logs()

        self.assertEqual(tag_counts['overwritten'], 1)
        self.assertNotIn('email', tag_counts)

        os.unlink(duplicate_lookup_file.name)

    # Test 7: Lookup file not found
    def test_missing_lookup_file(self):
        error_message = ""
        try:
            lookup = LookupTable("nonexistent_lookup.csv")
            lookup.load_lookup()
        except FileNotFoundError as e:
            error_message = str(e)

        self.assertEqual(error_message, "Lookup file not found: nonexistent_lookup.csv")
    
    # Test 8: Flow log file not found
    def test_missing_flow_log_file(self):
        lookup = LookupTable(self.lookup_file.name)
        tag_map = lookup.load_lookup()

        error_message = ""
        try:
            parser = LogParser("nonexistent_flow_logs.txt", tag_map)
            parser.process_logs()
        except FileNotFoundError as e:
            error_message = str(e)

        self.assertEqual(error_message, "Flow log file not found: nonexistent_flow_logs.txt")

    # Test 9: Invalid port number in the flow logs
    def test_invalid_port_in_flow_log(self):
        invalid_log_content = """2 123 eni-abc 10.0.0.1 192.0.2.1 12345 abc 6 10 5000 1620140761 1620140821 ACCEPT OK"""

        invalid_log_file = tempfile.NamedTemporaryFile(delete=False, mode='w+')
        invalid_log_file.write(invalid_log_content)
        invalid_log_file.close()

        lookup = LookupTable(self.lookup_file.name)
        tag_map = lookup.load_lookup()

        error_message = ""
        try:
            parser = LogParser(invalid_log_file.name, tag_map)
            parser.process_logs()
        except ValueError as e:
            error_message = str(e)

        self.assertEqual(error_message, "Invalid port number 'abc' at line 1")

        os.unlink(invalid_log_file.name)

    # Test 10: Output file generation
    def test_output_writer(self):
        lookup = LookupTable(self.lookup_file.name)
        tag_map = lookup.load_lookup()

        parser = LogParser(self.flow_log_file.name, tag_map)
        tag_counts, port_protocol_counts = parser.process_logs()

        writer = OutputWriter(tag_counts, port_protocol_counts, self.output_file.name)
        writer.write_output()

        with open(self.output_file.name, 'r') as f:
            output_content = f.read()

        self.assertIn("Tag Counts:", output_content)
        self.assertIn("email,1", output_content)
        self.assertIn("secure,1", output_content)
        self.assertIn("Untagged,1", output_content)
        self.assertIn("Port,Protocol,Count", output_content)

if __name__ == '__main__':
    unittest.main()
