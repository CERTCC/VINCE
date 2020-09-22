# September 2020 VINCE Announcement

In March 2020, the CERT/CC started using a custom-developed web-based platform for vulnerability coordination.  This platform is called VINCE: Vulnerability Information and Coordination Environment.  We have been slowly moving new vulnerability reports to VINCE and inviting vendors to VINCE on a case-by-case basis.

VINCE represents a significant change in how we perform vulnerability coordination.  Change has costs, and we realize that we are asking you to share these costs.  We believe the investment will pay off by reducing per-case effort, improving scalability and coverage, and maturing the state of coordinated vulnerability disclosure practice.

We are now actively transitioning to VINCE as the primary means to

* receive vulnerability reports
* notify vendors about potential vulnerabilities
* discuss and coordinate vulnerability reports before public disclosure
* allow vendors to provide status and vendor statements
* review and publish vulnerability notes
* allow vendors to manage their contact information

Some changes of note:

* We are intentionally stepping back from the role of central communications hub and mediator of all communications.  Our default stance is that reporters (researchers) and vendors will all participate in a shared per-case discussion forum in VINCE.  There are features in VINCE that support private communication between CERT/CC and vendors, but we advocate a more collaborative and efficient coordination model, thus the shared case discussion forum.

* Expect less and less email from us, including PGP email.  Notifications for new vulnerability reports will be made primarily through VINCE.

* VINCE sends notification mail From: <cert+donotreply@cert.org>.  Notifications are not PGP signed or encrypted and do not contain case details or other sensitive information.

* <cert@cert.org> (with a VU# ID in the subject please) still works, and <cert+donotreply@cert.org> is effectively <cert@cert.org>, but we encourage you to at least start testing VINCE.

*  We recognize that using many different web platforms for vulnerability coordination will not scale well.  Our proposed solution is an API.  While initially designed for VINCE, we see the need for a global interoperability standard, and welcome testing, feedback, and feature requests for the API.  API documentation: https://vuls.cert.org/confluence/display/VIN/API

As of yet there is no deadline or requirement to switch to VINCE, and we are still handling some coordination through PGP email.  However, as the transition continues, email and PGP will become a secondary channel for coordination and not receive the same level of service as VINCE.

We invite and encourage you to register for a VINCE account: https://kb.cert.org/vince/

The model is that individuals create VINCE accounts, then those VINCE users are assigned to one or more vendor groups.  An authorized VINCE user can be given administrative privileges to manage the vendor group.  A VINCE vendor group is roughly analogous to a PSIRT.

We take considerable care to properly associate user accounts with vendor groups.  We use our existing contacts, PGP, and other evidence to verify associations.  After you register for a VINCE account, verification may cause delay before we associate you with a vendor group.  Providing evidence (e.g., PGP-signed mail) of your association with a vendor will speed up the verification process.

VINCE documentation: https://vuls.cert.org/confluence/display/VIN/VINCE+Documentation
