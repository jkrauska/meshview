#!/usr/bin/env python3
"""
Wrapper script to analyze message size distribution from Meshview packets.
Calls inspect_packets.py and creates a histogram of text message sizes.
"""

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

# Global for bucket size
BUCKET_SIZE = 5


def create_histogram(sizes, width=60, bucket_size=5):
    """Create a text-based histogram of message sizes with bucketing."""
    if not sizes:
        return "No data to display"
    
    # Create buckets
    buckets = {}
    min_size = min(sizes)
    max_size = max(sizes)
    
    # Determine bucket ranges
    min_bucket = (min_size // bucket_size) * bucket_size
    max_bucket = ((max_size // bucket_size) + 1) * bucket_size
    
    # Initialize all buckets
    for bucket_start in range(min_bucket, max_bucket, bucket_size):
        bucket_end = bucket_start + bucket_size - 1
        buckets[(bucket_start, bucket_end)] = 0
    
    # Fill buckets with counts
    for size in sizes:
        bucket_start = (size // bucket_size) * bucket_size
        bucket_end = bucket_start + bucket_size - 1
        buckets[(bucket_start, bucket_end)] += 1
    
    # Remove empty buckets and sort
    non_empty_buckets = [(k, v) for k, v in buckets.items() if v > 0]
    non_empty_buckets.sort(key=lambda x: x[0][0])
    
    # Find max count for scaling
    max_count = max(count for _, count in non_empty_buckets) if non_empty_buckets else 1
    
    # Create histogram
    lines = []
    lines.append(f"\nMessage Size Distribution ({bucket_size}-byte buckets)")
    lines.append("=" * (width + 25))
    
    for (bucket_start, bucket_end), count in non_empty_buckets:
        # Calculate bar length
        bar_length = int((count / max_count) * width)
        bar = "█" * bar_length
        
        # Format the line
        lines.append(f"{bucket_start:3d}-{bucket_end:3d} bytes │{bar} {count}")
    
    lines.append("=" * (width + 25))
    
    return "\n".join(lines)


def analyze_messages(database="packets.db", count=100, channel=None):
    """
    Run inspect_packets.py and analyze message sizes.
    
    Args:
        database: Path to the database file
        count: Number of packets to analyze
        channel: Optional channel name to filter by
    """
    # Build command
    cmd = [
        "python3",
        "inspect_packets.py",
        database,
        "-p", "1",  # TEXT_MESSAGE_APP
        "-n", str(count),
        "--json"
    ]
    
    if channel:
        cmd.extend(["-c", channel])
    
    # Run the command
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Error running inspect_packets.py: {e}", file=sys.stderr)
        print(f"stderr: {e.stderr}", file=sys.stderr)
        return 1
    except FileNotFoundError:
        print("Error: inspect_packets.py not found in current directory", file=sys.stderr)
        return 1
    
    # Parse JSON output
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON output: {e}", file=sys.stderr)
        print(f"Output was: {result.stdout[:200]}", file=sys.stderr)
        return 1
    
    # Extract message sizes
    sizes = []
    packets = data.get("packets", [])
    
    for packet in packets:
        decoded_payload = packet.get("decoded_payload")
        if decoded_payload and decoded_payload.get("type") == "text_message":
            size = decoded_payload.get("size")
            if size is not None:
                sizes.append(size)
    
    # Display results
    print(f"\nAnalyzed {len(packets)} text message packet(s)")
    print(f"Found {len(sizes)} message(s) with size information")
    
    if sizes:
        print(f"\nStatistics:")
        print(f"  Min size: {min(sizes)} bytes")
        print(f"  Max size: {max(sizes)} bytes")
        print(f"  Avg size: {sum(sizes)/len(sizes):.1f} bytes")
        print(f"  Total: {len(sizes)} messages")
        
        print(create_histogram(sizes, bucket_size=BUCKET_SIZE))
    else:
        print("\nNo text messages found with size information.")
    
    return 0


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Analyze text message size distribution from Meshview database",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze last 100 text messages
  %(prog)s
  
  # Analyze last 500 text messages
  %(prog)s -n 500
  
  # Analyze text messages from specific database
  %(prog)s mydata.db
  
  # Analyze text messages from specific channel
  %(prog)s -c LongFast
  
  # Combine database and channel filter
  %(prog)s packets.db -c LongFast -n 200
        """
    )
    
    parser.add_argument(
        "database",
        nargs="?",
        default="packets.db",
        help="Path to the SQLite database file (default: packets.db)"
    )
    
    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=100,
        help="Number of packets to analyze (default: 100)"
    )
    
    parser.add_argument(
        "-c",
        "--channel",
        type=str,
        help="Filter by channel name (e.g., 'LongFast', 'ShortFast')"
    )
    
    parser.add_argument(
        "-b",
        "--bucket-size",
        type=int,
        default=5,
        help="Size of histogram buckets in bytes (default: 5)"
    )
    
    args = parser.parse_args()
    
    # Store bucket_size in a global or pass it through
    global BUCKET_SIZE
    BUCKET_SIZE = args.bucket_size
    
    exit_code = analyze_messages(
        database=args.database,
        count=args.count,
        channel=args.channel
    )
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
