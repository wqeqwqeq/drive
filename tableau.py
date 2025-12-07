import os
from dotenv import load_dotenv
import tableauserverclient as TSC


class TableauServerWrapper:
    """Wrapper class for Tableau Server Client."""

    def __init__(self, server_url: str, site_id: str = "", env_file: str = ".env"):
        load_dotenv(env_file)
        self.server_url = server_url
        self.site_id = site_id
        self.server = TSC.Server(server_url, use_server_version=True)
        self._auth = None

    def sign_in(self):
        """Sign in using PAT or username/password based on env config."""
        auth_method = os.getenv("TABLEAU_AUTH_METHOD", "username_password")

        if auth_method == "pat":
            pat_name = os.getenv("TABLEAU_PAT_NAME")
            pat_value = os.getenv("TABLEAU_PAT_VALUE")
            self._auth = TSC.PersonalAccessTokenAuth(pat_name, pat_value, site_id=self.site_id)
        else:
            username = os.getenv("TABLEAU_USERNAME")
            password = os.getenv("TABLEAU_PASSWORD")
            self._auth = TSC.TableauAuth(username, password, site_id=self.site_id)

        self.server.auth.sign_in(self._auth)

    def sign_out(self):
        """Sign out from Tableau Server."""
        self.server.auth.sign_out()

    def list_workbooks_in_site(self) -> list:
        """List all workbooks in the site."""
        return list(TSC.Pager(self.server.workbooks))

    def list_views_in_site(self) -> list:
        """List all views in the site."""
        return list(TSC.Pager(self.server.views))

    def list_views_in_workbook(self, workbook_id: str) -> list:
        """List all views in a specific workbook."""
        workbook = self.server.workbooks.get_by_id(workbook_id)
        self.server.workbooks.populate_views(workbook)
        return list(workbook.views)

    def download_view_image_by_id(self, view_id: str, filepath: str = None) -> bytes:
        """Download a view as an image."""
        view = self.server.views.get_by_id(view_id)
        self.server.views.populate_image(view)
        image_data = view.image

        if filepath:
            with open(filepath, "wb") as f:
                f.write(image_data)

        return image_data

    def download_workbook_by_id(self, workbook_id: str, filepath: str = None) -> str:
        """Download a workbook file."""
        return self.server.workbooks.download(workbook_id, filepath)

    def __enter__(self):
        self.sign_in()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.sign_out()
