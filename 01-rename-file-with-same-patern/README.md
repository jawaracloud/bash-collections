# Script Purpose:

Description: This Bash script is designed to rename files in the current directory by removing a specified pattern from their names.
Usage: It takes two variables, patern and extentions, to specify the pattern to be removed and the file extension to match, respectively. It then renames all matching files by removing the specified pattern.

# Usage Example:

Suppose you have files in the current directory with names like "your-patern-file1.yaml," "your-patern-file2.yaml," and so on, and you want to remove the "your-patern-" prefix from their names.
You would set patern="your-patern" and extentions="yaml", and then run the script. It would rename these files to "file1.yaml," "file2.yaml," and so on.

# How to Use:

Modify the patern and extentions variables to match your specific naming pattern and file extension.
Make the script executable using chmod +x script_name.sh if it's not already.
Run the script in the directory containing the files you want to rename.

**Note**: Ensure that you have a clear understanding of the naming pattern and file extension you want to work with when using this script.