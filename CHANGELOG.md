# VINCE Changelog

Version 1.50.3: 2022-09-16
==========================

Full support for CSAF 2.0 export of vulnerability Case
Fix for a number of Views to avoid digit parameter confusion
Add view CSAF and VINCE JSON to support download of Case data in machine-readable format
If upgrading, make sure you verify settings.py has new variables `CONTACT_PHONE` `ORG_POLICY_URL` and `ORG_AUTHORITY` populated.


Version 1.50.2: 2022-08-29
-=========================

Resolves issue of enumerating user_id and group_id - reported by Sharon Brizinov of Claroty Research [#51](https://github.com/CERTCC/VINCE/issues/51)
Removed lxml library no longer in use in requirements.txt - reported by dependabot via [#38](https://github.com/CERTCC/VINCE/pull/38)
Add [DISABLED] Keyword for users in `inactive` status in vincetrack `Teams` menu view.


Version 1.50.1: 2022-08-08
==========================

BugFix for API key generation issue. The generate_key method was disabled accidentally


# Version 1.50.0: 2022-07-19
============================

New MFA reset workflow

Allow comments when re-assigning tickets

Sorting improvements on VINCEComm Dashboard

Add Vul Note download button in VINCETrack

Fixed open redirect vulnerability (CVE-2022-25799)[https://nvd.nist.gov/vuln/detail/CVE-2022-25799] reported by Jonathan Leitschuh   [#45](https://github.com/CERTCC/VINCE/issues/45)

Bug Fixes

# Version 1.49.0: 2022-07-19
===========================

Contact Management Updates

Dependency Upgrades

Bug Fixes

# Version 1.48.0: 2022-05-13
=============================

Initial Open Source Release
