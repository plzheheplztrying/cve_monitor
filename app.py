import requests
from peewee import *
from datetime import datetime
import git
import os
import html  # For escaping HTML content

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
    """Generates the CVE HTML report."""
    html_content = """
    <html>
    <head>
        <title>CVE Data</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { background-color: #121212; color: #ffffff; padding-top: 50px; }
            .container { max-width: 90%; }
            .table { background-color: #1e1e1e; color: #ffffff; border: 1px solid #444444; }
            th, td { text-align: center; vertical-align: middle; padding: 12px 15px; border: 1px solid #444444; }
            th { background-color: #333333; }
            .table-striped tbody tr:nth-child(odd) { background-color: #252525; }
            .btn { background-color: #007bff; color: white; padding: 6px 12px; font-size: 14px; }
            .btn:hover { background-color: #0056b3; }
            .card { background-color: #333333; border: none; color: #ffffff; }
            .card-header { background-color: #444444; color: #ffffff; }
            .card-body { background-color: #1e1e1e; }
        </style>
    </head>
    <body>
        <div class="container py-5">
            <h1 class="text-center text-info mb-4">CVE Data Monitor</h1>
            <div class="row">
                <div class="col-12">
                    <div class="card">
                        <div class="card-header">
                            <h4 class="card-title">CVE Data Table</h4>
                        </div>
                        <div class="card-body">
                            <table class="table table-striped">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Full Name</th>
                                        <th>Description</th>
                                        <th>URL</th>
                                        <th>Created At</th>
                                    </tr>
                                </thead>
                                <tbody>
    """

    for entry in cve_data:
        html_content += f"""
            <tr>
                <td>{html.escape(str(entry['id']))}</td>
                <td>{html.escape(entry['full_name'])}</td>
                <td>{html.escape(entry['description'])}</td>
                <td><a href="{html.escape(entry['url'])}" class="btn btn-primary btn-sm" target="_blank">Link</a></td>
                <td>{html.escape(entry['created_at'])}</td>
            </tr>
        """

    html_content += """
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.5.3/dist/umd/popper.min.js"></script>
        <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
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
