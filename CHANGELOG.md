# VINCE Changelog


Version 2.1.9  2023-12-07

* Dependabot update recommendations: `cryptography` 41.0.3 to 41.0.6
* Fixed bug that prevented "Add Vulnerability" button from rerouting user to appropriate pages upon submission
* Integrated custom metrics into weekly reports on VINCE activity

Version 2.1.8  2023-11-08

* Dependabot update recommendations: `django` 3.2.20 to 3.2.23
* Restructured vendors tab on VINCE Track case page so that vendors table is paginated rather than indefinitely scrollable

Version 2.1.7  2023-10-30

* Added customization of MFA
* Added code to catch and correct Vul Note Reviews with data omissions that led to page load failures in certain circumstances


Version 2.1.6  2023-10-25

* Fixed bug that interfered in certain circumstances with the operation of the vendor filter button on the VINCEComm case page
* Dependabot update recommendations: `urllib3` 1.26.12 to 1.26.18
* Fixed bug that obstrcuted case assignment process for VINCETrack users with identical preferred usernames
* Adjusted code for asynchronous loading on ticket page to ensure it works on all ticket pages, including case request tickets
* Set up periodic autorefresh feature for VINCE Track ticket page
* Reformulated misleading UI labels for case transfer request process
* Resolved Issue by simpifying/correcting search code & disambiguating labels in report views
* Added AI/ML systems checkbox to public & VINCE Comm vul report form, routing of AI/ML-related tickets


Version 2.1.5  2023-09-21

* Enhanced operation of VINCEComm case discussion section, moving focus to editable div when the user chooses to edit a post
* Added dropdown menu to VINCETrack quicksearch bar, optimizing search by enabling swifter specification of advanced search settings
* Replaced certain switch-paddle checkboxes on VINCE forms with tswitch UI to make them easier to use
* Fixed bug that generated duplicates in the list of vendors on certain VINCEComm case pages


Version 2.1.4  2023-08-30

* Automated annual update to VINCE copyright date in footer
* Dependabot update recommendations: `django` 3.2.19 to 3.2.20
* Replaced malfunctioning dropdown menu in original report tab on VINCETrack case page with link to case request ticket
* Added functionality to VINCE Comm status page for muting & unmuting cases, with alerts responding to selected affectedness status
* Set up periodic autorefresh feature for the VINCE Track Triage page

Version 2.1.3  2023-08-09

* More tabs on VinceTrack Case page updated for asynchronous loading.
* Dependabot update recommendations: `cryptography` 41.0.0 to 41.0.3, `certifi` 2022.9.24 to 2023.7.22
* Enhanced printability of VINCEComm Case pages by removing unnecessary content on print and adding more detailed title to case page
* Remove duplicate settings.py to avoid confusion.
* Removed option to sort large numbers of vendors alphabetically on published vulnotes, preventing JavaScript bug
* Introduced code that automatically schedules weekly reports on VINCE statistics to be sent via email to appropriate recipients


Version 2.1.2  2023-06-09

* VinceTrack CaseView,VinceCommUserView updated for Asynchronous calls for tab-based browsing.
* Fixed GH Issue #111 PDF Links not working
* Updated Vendor approval workflow with time lapse of 2 weeks of no-response from Vendor Admin
* Fix bounce issues of creating tickets for dead/disabled users.
* Dependabot security recommendations PyPi `cryptography` 39.0.1 to 41.0.0, `requests` 2.281 to 2.31.0, `django-ses` from 3.2.2 to 3.5.0
* Fixed vincepubviews multiple choice field Years to be dynamic

Version 2.1.1  2023-05-02

* Security updates fixing a number of dependencies - sqlparse, redis (GHSA-rrm6-wvj7-cwh2,CVE-2023-28859,CVE-2023-28858)
* Updates (UAR) workflow for User joining Vendor Group GH Issue #94
* INL Code updates to perform Product/Version for CVE records GH PR #104
* INL Code updates for PDF download of VulNote GH PR #104
* Async requests for VinceTrack Contacts to reduce page wait times
* Check for Bounces before sending emails from vince/mailer.py
* Add TERMS_URL to ensure Terms & Conditions are flexible
* Fix CVSS Translator GH Issue #105
* Check for notification-only addresses and provide error on Signup


Version 2.0.7  2023-03-20

* Security updates Django to 3.2.18 CVE-2023-24580, Remove python-futures (no longer used) GH Issues #91 #90 (Dependabot)
* Support User Approve Request (UAR) new workflow for User joining Vendor Group GH Issue #94
* Allow Tracking ID's to be added to Cases when user belongs to multiple groups (CaseTracking) reported by VINCE user.
* Move from initial to instance on Form Class inits() to modify existing data in Models/Forms pair
* Move more browser UI information to async data requests, less templates.
* Remove `marquee`, `command` and `style` tags from supported markdown_helpers  lib.vince.markdown_helpers - reported by VINCE user.


Version 2.0.6  2023-01-23

* Removed Edit Vulnerability button superfluous GHIssue #77
* Updates to CVE publish buttons and automatic close of CVE modal on error
* Modify CVEAffectedProduct.version_affected vince models.py for CVE5JSON
* Bug fix newcomment not new_comment in vince/views.py
* Add "Notify anyway" button routine for already notified vendor.

## Version 2.0.5  2023-01-04

* Update to CVE2.1 Services Publish using CVE5 JSON
* More Async functions for vendor status views
* Added more common libraries to lib/vince/utils
* Added a mute_lib.py to support mute a Case for a user in automated way
* Fixed a number of small bugs in max length in FORM submissions and S3 sensitive filenames

## Version 2.0.4: 2022-12-20

* Added Filter to CaseView in VinceComm
* Addition of more Async functions for non-interactive queries
* Fixing of slow performance on allvendors view to use Django Aggregate and Filter/Q functions
* Friendly errors and fixes for logging to add IP address of remote client


## Version 2.0.3: 2022-12-14

* Major upgrade to Django 3.2 LTS target end byt 2024. Fixes related to Django upgrade in all libraries.
* Aded new QuerySet Paging library for performance extend chain with chainqs for QuerySet
* Asynchronous calls for most vinny/views via JSON through asyncLoad class
* Provide API Views 404 with JSON generic error
* Allow Session or API Token authentication to support API access from browser
* Provide better HTML text on access/permission violations by User.
* Fixes to CVE management API with CVE services 2.1 and CVEJSON5 support
* CSAF enchancements including TLP setup. Pending Customer engagement details publishing.
* Fix number of logging to include relevant data as part of log message

## Version 1.50.6: 2022-11-04

* Allow Vendor Association when Ticket is associated with a Case
* Adding Download HTML per INL request GH Issue #60
* Avoid Alert severity colors to buttons that don't do deletes/sensitive actions - UI feedback.
* Show MFA type for users in VinceTrack to support troubleshooting Users
* Catch errors on failure to email when a Post is submitted.

## Version 1.50.5: 2022-10-25

* Updates to settings_.py to match public GitHub
* UI tweaks for Loading div, asynchronous search via delaySearch
* Add Access-Control-Origin header to CSAF output for Secvisogram
* Fix Python Pickle Code Injection vulnerability reported by Rapid7 researcher Marcus Chang CVE-2022-40238
* Address reported failure with better error reporting from Encrypt-and-Send
* Avoid TimeZone spurious warning errors flooding logs

## Version 1.50.4: 2022-10-05

* UI improvements for vincetrack for search experience
* Performance tweaks for Tickets search use $queryset.count() instead len($queryset) when pagination is used
* Fix HTML injection vulnerabilities reported by Rapid7 researcher Nick Sanzotta (CVE-2022-40248,CVE-2022-40257)


## Version 1.50.3: 2022-09-16

* Full support for CSAF 2.0 export of vulnerability Case
* Fix for a number of Views to avoid digit parameter confusion
* Add view CSAF and VINCE JSON to support download of Case data in machine-readable format
* If upgrading, make sure you verify settings.py has new variables `CONTACT_PHONE` `ORG_POLICY_URL` and `ORG_AUTHORITY` populated.


## Version 1.50.2: 2022-08-29

* Resolves issue of enumerating user_id and group_id - reported by Sharon Brizinov of Claroty Research [#51](https://github.com/CERTCC/VINCE/issues/51)
* Removed lxml library no longer in use in requirements.txt - reported by dependabot via [#38](https://github.com/CERTCC/VINCE/pull/38)
* Add [DISABLED] Keyword for users in `inactive` status in vincetrack `Teams` menu view.


## Version 1.50.1: 2022-08-08

* BugFix for API key generation issue. The generate_key method was disabled accidentally


## Version 1.50.0: 2022-07-19

* New MFA reset workflow
* Allow comments when re-assigning tickets
* Sorting improvements on VINCEComm Dashboard
* Add Vul Note download button in VINCETrack
* Fixed open redirect vulnerability (CVE-2022-25799)[https://nvd.nist.gov/vuln/detail/CVE-2022-25799] reported by Jonathan Leitschuh   [#45](https://github.com/CERTCC/VINCE/issues/45)
* Bug Fixes

## Version 1.49.0: 2022-07-19

* Contact Management Updates
* Dependency Upgrades
* Bug Fixes

## Version 1.48.0: 2022-05-13

* Initial Open Source Release
