# Illumio-internship-assessment

# Flow Log Parser

## Problem Description

Write a program that can parse a file containing **flow log data** and map each row to a **tag** based on a **lookup table**. 

- The **lookup table** is defined as a CSV file with 3 columns:  
  - `dstport`, `protocol`, and `tag`.  
- The **`dstport` and `protocol` combination** determines which tag is applied to each log entry.

---

## Expected Output

The program generates an output file containing the following:

1. **Count of Matches for Each Tag:**  
    Example:
    Tag Counts: 
    Tag,Count 
    email,5 
    secure,3 
    management,2 
    Untagged,4

2. **Count of Matches for Each Port/Protocol Combination:**  
    Example:
    Port/Protocol Combination Counts: 
    Port,Protocol,Count 
    25,tcp,5 
    443,tcp,3 
    50,esp,2 
    8080,tcp,4


---

## How to Clone and Run the Repository

### **Step 1: Clone the Repository**

```bash
git clone https://github.com/your-username/your-repo-name.git
cd your-repo-name
```

### **Step 2: Prepare Input Files**
    Ensure flow_logs.txt and lookup_table.csv are in the root directory.

### **Step 3: Run the Program**

```bash
python3 main.py
```

### **Step 4: Run the Tests**
```bash
python3 test_main.py
```
---

## Assumptions

### **Log Version:**
- The program **only supports version 2** of AWS VPC flow logs.
- Logs with other versions are **ignored**.

### **Log Structure:**
- Assumes each log entry follows the [default AWS VPC flow log format](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html).
- Each line contains at least **13 fields** (as per version 2 specification).

### **Field Positions:**
- **Destination Port** is always in the **7th field** (index `6`).
- **Protocol Number** is always in the **8th field** (index `7`).
- These positions are consistent across all log entries.

### **Protocol Handling Assumptions:**
- **Case Insensitivity:** Protocol names in the lookup table are case-insensitive (e.g., `TCP`, `tcp`, and `Tcp` are treated the same).

### **Lookup Table Assumptions:**
- **CSV Format:** The first row is a **header** and is skipped during processing.
- **Unique Mappings:**  
    - Each `(dstport, protocol)` combination is assumed to be **unique** in the lookup table.  
    - If duplicates exist, the program will use the **last occurrence**.
- **Empty or Invalid Rows:**  
    - Rows with fewer than **3 columns** are considered **invalid** and are skipped.

### **Data Processing Assumptions:**
- **Counting Behavior:** Both **accepted** and **rejected** flow log entries are processed equally.

### **Input/Output Assumptions:**
- **Input Files:**  
    - Files like `flow_logs.txt` and `lookup_table.csv` are assumed to be in **plain ASCII text**.
- **Output Format:**  
    - **Port/Protocol Combination Counts** include **all combinations** from the flow logs, not just those present in the lookup table.

### **Error Handling Assumptions:**
- **Invalid Log Lines:**  
    - Malformed log lines (missing fields or incorrect version) are **skipped silently**.
- **Missing Lookup Mappings:**  
    - If the lookup table is **empty** or missing mappings, entries are tagged as **"Untagged"**.
- **Graceful Degradation:**  
    - The program **will not crash** if files are empty; instead, it generates an output with **zero counts**.
---


## Future Scope

### Multithreading for Large files:
- If the flow log files or the lookup table grow significantly large, processing time will increase.
- Implement multithreading to divide the workload across multiple CPU cores.
- **Pseudocode:**

```bash
1. Read the flow log file.

2. Divide the file into 4 equal parts (chunks).

3. For each chunk:
   - Create a separate thread to process that chunk.

4. In each thread:
   - Read each line in the chunk.
   - Extract destination port and protocol.
   - Map the tag using the lookup table.
   - Count the tags and port/protocol combinations.

5. After all threads finish:
   - Combine (merge) the results from all threads.

6. Write the final combined results to the output file.
```
