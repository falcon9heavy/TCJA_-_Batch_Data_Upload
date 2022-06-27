"""ThreatConnect Job App"""
# standard library
import csv
from typing import TYPE_CHECKING

# third-party
from tcex.exit import ExitCode

# first-party
from job_app import JobApp  # Import default Job App Class (Required)

if TYPE_CHECKING:
    # third-party
    from tcex import TcEx
    from tcex.api.tc.v2.batch import Batch
    from tcex.api.tc.v2.batch.indicator import Address
    from tcex.sessions.external_session import ExternalSession


class App(JobApp):
    """Job App"""

    def __init__(self, _tcex: 'TcEx') -> None:
        """Initialize class properties."""
        super().__init__(_tcex)

        # properties
        self.batch: 'Batch' = self.tcex.v2.batch(self.inputs.model.tc_owner)
        self.session = None

    def setup(self) -> None:
        """Perform prep/setup logic."""
        # using tcex session_external to get built-in features (e.g., proxy, logging, retries)
        self.session: 'ExternalSession' = self.tcex.session_external

        # setting the base url allow for subsequent call to be made by only
        # providing the API endpoint/path.

        """ 
        Modify this code branch to ingest a CSV file from S3 bucket.
        
        """


        self.session.base_url = 'https://feodotracker.abuse.ch'
        # url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

    def run(self) -> None:
        """Run main App logic."""

        with self.session as s:
            r = s.get('/downloads/ipblocklist.csv')

            if r.ok:
                decoded_content: str = r.content.decode('utf-8').splitlines()

                reader: object = csv.reader(decoded_content, delimiter=',', quotechar='"')
                for row in reader:
                    # CSV headers
                    # first_seen_utc, dst_ip, dst_port,	c2_status, last_online, malware

                    # skip comments and CSV headers
                    if row[0].startswith('#') or row[0].startswith('first_seen_utc'):
                        continue

                    # create batch entry
                    indicator_value: str = row[1]
                    ip_address: Address = self.batch.address(
                        indicator_value, rating='3.0', confidence='50'
                    )

                    # apply malware type to indicator
                    ip_address.tag(row[5])

                    # apply malware type as an attribute
                    ip_address.attribute('Description', row[5], True)

                    # apply port to custom attribute called Port
                    ip_address.attribute('Destination Port', row[2], True)

                    # apply the observation day/time
                    ip_address.attribute('First Observed', row[0], True)

                    # load it all up
                    self.batch.save(ip_address)
            else:
                self.tcex.exit(ExitCode.SUCCESS, 'Failed to download CSV data.')

        # submit batch job
        batch_status: list = self.batch.submit_all()
        self.log.info(f'batch-status={batch_status}')

        self.exit_message = (  # pylint: disable=attribute-defined-outside-init
            'Downloaded data and create batch job.'
        )
