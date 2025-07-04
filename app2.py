import requests
from peewee import *
from datetime import datetime
import git
import os

# GitHub repository details
GITHUB_REPO_PATH = '/home/alex/cve_monitor'
GITHUB_BRANCH = 'main'

# Fetch GitHub credentials from environment variables
GITHUB_USERNAME = os.getenv("GITHUB_USERNAME")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

if not GITHUB_USERNAME or not GITHUB_TOKEN:
    print("Error: GitHub credentials not set. Please configure environment variables.")
    exit(1)

# Database setup
db = SqliteDatabase("cve.sqlite")

class CVE_DB(Model):
    id = IntegerField()
    full_name = CharField(max_length=1024)
    description = CharField(max_length=4098)
    url = CharField(max_length=1024)
    created_at = CharField(max_length=128)

    class Meta:
        database = db

db.connect()

def write_html(cve_data):
    """Generates the CVE HTML report with a modern light theme."""
    html_content = """
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
        <title>CVE Data</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { background-color: #f8f9fa; }
            .container { max-width: 95%; margin-top: 40px; }
            .card { box-shadow: 0 4px 8px rgba(0, 0, 0, 0.05); border-radius: 16px; }
            .card-header { background-color: #007bff; color: white; font-weight: bold; border-radius: 16px 16px 0 0; }
            .table th, .table td { vertical-align: middle; }
            a.btn-sm { font-size: 0.85rem; padding: 4px 10px; }
            .table-hover tbody tr:hover { background-color: #f1f1f1; }
        </style>
    </head>
    <body>
        <div class="container">
            <h2 class="text-center text-primary mb-4">🛡️ CVE Data Monitor</h2>
            <div class="card">
                <div class="card-header">
                    CVE Records Overview
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover align-middle">
                            <thead class="table-light">
                                <tr>
                                    <th scope="col">ID</th>
                                    <th scope="col">Full Name</th>
                                    <th scope="col">Description</th>
                                    <th scope="col">URL</th>
                                    <th scope="col">Created At</th>
                                </tr>
                            </thead>
                            <tbody>
    """

    for entry in cve_data:
        html_content += f"""
            <tr>
                <td>{entry['id']}</td>
                <td>{entry['full_name']}</td>
                <td>{entry['description']}</td>
                <td><a href="{entry['url']}" class="btn btn-sm btn-outline-primary" target="_blank">View</a></td>
                <td>{entry['created_at']}</td>
            </tr>
        """

    html_content += """
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    </body>
    </html>
    """

    with open("cve_data.html", "w") as f:
        f.write(html_content)

def fetch_cve_data():
    """Fetches CVE data from the SQLite database."""
    cve_data = []
    query = CVE_DB.select().order_by(CVE_DB.created_at.desc())
    
    for entry in query:
        cve_data.append({
            "id": entry.id,
            "full_name": entry.full_name,
            "description": entry.description,
            "url": entry.url,
            "created_at": entry.created_at
        })

    return cve_data

def push_to_github():
    """Pushes the generated HTML file to GitHub using environment-based authentication."""
    try:
        repo = git.Repo(GITHUB_REPO_PATH)
        repo.git.add('cve_data.html')
        repo.index.commit('Update CVE data HTML file')

        origin = repo.remote(name='origin')
        origin.set_url(f"https://{GITHUB_USERNAME}:{GITHUB_TOKEN}@github.com/{GITHUB_USERNAME}/cve_monitor.git")
        origin.push()

        print("cve_data.html pushed to GitHub successfully!")
    except Exception as e:
        print(f"Error occurred while pushing to GitHub: {e}")

def main():
    """Main function to fetch CVE data, generate HTML, and push to GitHub."""
    cve_data = fetch_cve_data()
    if cve_data:
        write_html(cve_data)
        print("CVE data has been written to cve_data.html.")
        push_to_github()
    else:
        print("No CVE data found in the database.")

if __name__ == "__main__":
    main()
