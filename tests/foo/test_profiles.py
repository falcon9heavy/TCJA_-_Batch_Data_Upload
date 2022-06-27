"""Test case template for App testing."""
# standard library
import os

# third-party
from tcex_testing.test_case import TestCaseJob

from .custom_feature import CustomFeature  # pylint: disable=relative-beyond-top-level


# pylint: disable=useless-super-delegation,too-many-function-args
class TestProfiles(TestCaseJob):
    """TcEx App Testing Template."""

    def setup_class(self) -> None:
        """Run setup logic before all test cases in this module."""
        super().setup_class()
        self.custom = CustomFeature()  # pylint: disable=attribute-defined-outside-init
        if os.getenv('SETUP_CLASS') is None:
            self.custom.setup_class(self)
        # enable auto-update of profile data
        self.enable_update_profile = True  # pylint: disable=attribute-defined-outside-init

    def setup_method(self) -> None:
        """Run setup logic before test method runs."""
        super().setup_method()
        if os.getenv('SETUP_METHOD') is None:
            self.custom.setup_method(self)

    def teardown_class(self) -> None:
        """Run setup logic after all test cases in this module."""
        if os.getenv('TEARDOWN_CLASS') is None:
            self.custom.teardown_class(self)
        super().teardown_class()
        # disable auto-update of profile data
        self.enable_update_profile = False  # pylint: disable=attribute-defined-outside-init

    def teardown_method(self) -> None:
        """Run teardown logic after test method completes."""
        if os.getenv('TEARDOWN_METHOD') is None:
            self.custom.teardown_method(self)
        super().teardown_method()

    def test_profiles(
        self,
        profile_name: str,
        monkeypatch: object,
        pytestconfig: object,
    ) -> None:  # pylint: disable=unused-argument
        """Run pre-created testing profiles."""
        # initialize profile
        self.aux.init_profile(
            app_inputs=self.app_inputs,
            monkeypatch=monkeypatch,
            profile_name=profile_name,
            pytestconfig=pytestconfig,
        )

        # run custom test method before run method
        self.custom.test_pre_run(
            self, self.aux.profile.data, monkeypatch if self.run_method == 'inline' else None
        )

        assert self.run_profile() in self.aux.profile.model.exit_codes

        # run custom test method before validation
        self.custom.test_pre_validate(self, self.aux.profile.data)

        self.aux.validator.threatconnect.batch(self.aux.profile)

        # validate exit message
        if self.aux.profile.model.exit_message:
            self.aux.validate_exit_message(self.aux.profile.model.exit_message)
