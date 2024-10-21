# The purpose of this function is to read in a CSV file.
def read_csv(path):
    # 1. Open the file for reading.
    table_file = open(path, "r")
    # 2. Store each line.
    table = table_file.readlines()
    # 3. Create an empty list to store each processed row.
    table_list = []
    # 4. For each line in the file:
    for line in table:
        # split it into a list of strings by the delimiter using .split(","), 
        # remove any leading/trailing spaces using strip(), and append resulting list to table_list
        parsed_line = [element.strip() for element in line.strip().split(",")]
        table_list.append(parsed_line)
        
    # Close the file and return table_list.
    table_file.close()
    return table_list
