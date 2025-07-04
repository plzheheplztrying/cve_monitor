output_file = "output.txt"

# Read the last commit number from the file
def get_last_commit_number():
    try:
        with open(output_file, "r") as f:
            lines = f.readlines()
            if lines:
                last_line = lines[-1].strip()
                if last_line.startswith("commit"):
                    return int(last_line.split()[1])
    except FileNotFoundError:
        return 0
    return 0

# Append the next commit
def append_commit():
    last_commit = get_last_commit_number()
    next_commit = last_commit + 1
    with open(output_file, "a") as f:
        f.write(f"commit {next_commit}\n")

if __name__ == "__main__":
    append_commit()
    print(f"Appended commit to {output_file}")
