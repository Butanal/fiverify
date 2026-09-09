import pytest

import fixtures
from fiverify.profile import Profile


@pytest.fixture(scope="session")
def pki():
    return fixtures.make_pki()


@pytest.fixture(scope="session")
def profile():
    return Profile.bundled()


@pytest.fixture
def trusted(profile, pki):
    return profile.with_anchors(pki.anchors())
