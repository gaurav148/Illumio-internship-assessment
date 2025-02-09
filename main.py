import csv
import collections
import time

class LogParser:
    # Maps protocol numbers to protocol names
    PROTOCOL_MAP = {
        '6': 'tcp',
        '17': 'udp',
        '1': 'icmp'
    }

    def __init__(self, log_file, tag_map):
        # Initialize with the flow log file path and the lookup tag map
        self.log_file = log_file
        self.tag_map = tag_map
        self.tag_counts = collections.defaultdict(int)
        self.port_protocol_counts = collections.defaultdict(int)

    def process_logs(self):
        # Reads the flow log file line by line and processes each entry
        try:
            with open(self.log_file, 'r') as file:
                for line_number, line in enumerate(file, start=1):
                    parts = line.strip().split() 
                    if len(parts) < 13 or parts[0] != '2':  # Skip invalid lines and ensure version is 2
                        continue

                    dst_port = parts[6]
                    protocol = self.PROTOCOL_MAP.get(parts[7], parts[7]).lower()  # Map protocol number to protocol name

                    if not dst_port.isdigit():
                            raise ValueError(f"Invalid port number '{dst_port}' at line {line_number}")


                    key = (dst_port, protocol)
                    tag = self.tag_map.get(key, "Untagged")  # Get the corresponding tag from the lookup table, default to "Untagged" if not found

                    self.tag_counts[tag] += 1  # Increment the tag count
                    if key in self.tag_map:
                        self.port_protocol_counts[key] += 1  # Increment the count for the matched port/protocol combination
        
        except FileNotFoundError:
            raise FileNotFoundError(f"Flow log file not found: {self.log_file}")
        
        return self.tag_counts, self.port_protocol_counts


class LookupTable:
    def __init__(self, lookup_file):
        # Initialize with the lookup table file path
        self.lookup_file = lookup_file

    def load_lookup(self):
        # Loads the lookup table from a CSV file and returns a dictionary mapping (dst_port, protocol) to tag
        tag_map = {}
        try:
            with open(self.lookup_file, 'r') as file:
                reader = csv.reader(file)
                header = next(reader, None)

                if header is None:
                    return tag_map  # Empty file, return empty map
                
                for row in reader:
                    if len(row) < 3:
                        continue
                    dst_port, protocol, tag = row[0].strip(), row[1].strip().lower(), row[2].strip()
                    tag_map[(dst_port, protocol)] = tag
       
        except FileNotFoundError:
            raise FileNotFoundError(f"Lookup file not found: {self.lookup_file}")
        
        return tag_map


class OutputWriter:
    def __init__(self, tag_counts, port_protocol_counts, output_file):
        # Initialize with tag counts, port/protocol counts, and output file path
        self.tag_counts = tag_counts
        self.port_protocol_counts = port_protocol_counts
        self.output_file = output_file

    def write_output(self):
        # Writes the results (tag counts and port/protocol combination counts) to the output file
        with open(self.output_file, 'w') as file:
            file.write("Tag Counts:\n")
            file.write("Tag,Count\n")
            for tag, count in sorted(self.tag_counts.items(), key=lambda x: x[1], reverse=True):
                file.write(f"{tag},{count}\n")

            file.write("\nPort/Protocol Combination Counts:\n")
            file.write("Port,Protocol,Count\n")
            for (port, protocol), count in sorted(self.port_protocol_counts.items(), key=lambda x: x[1], reverse=True):
                file.write(f"{port},{protocol},{count}\n")


def main(flow_log_file, lookup_file, output_file):
    # Main function to coordinate loading the lookup table, processing logs, and writing output

    lookup = LookupTable(lookup_file)
    tag_map = lookup.load_lookup()  # Load the lookup table

    parser = LogParser(flow_log_file, tag_map)
    tag_counts, port_protocol_counts = parser.process_logs()  # Process the logs to get tag and port/protocol counts

    writer = OutputWriter(tag_counts, port_protocol_counts, output_file)
    writer.write_output()  # Write the processed results to the output file

    print(f"Results written to {output_file}")


if __name__ == "__main__":
    flow_log_file = "flow_logs.txt"
    lookup_file = "lookup_table.csv"
    output_file = "output_results.txt"  # Output file for the results

    # Calculating the execution time of the entire operation
    start_time = time.time()

    main(flow_log_file, lookup_file, output_file)  # Execute the main function

    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000  # Convert execution time to milliseconds

    print(f"Total Execution Time: {execution_time_ms:.2f} ms")
