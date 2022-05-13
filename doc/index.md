VINCE documentation
====================

VINCE, the Vulnerability Information and Coordination Environment, is a cloud-based, web application written in Python (Django) for coordinated vulnerability disclosure. It was developed due to a lack of existing ticketing tools for multi-party vulnerability coordination.

Key Features
--------------

VINCE was designed for vulnerability coordination teams who need to manage communications about vulnerabilties with multiple parties.  It intends to replace the use of encrypted mail communication and bring all relevant parties to the platform to collaborate, discuss, and agree on an embargo date. In this context *'relevant parties'* may be reporters, researchers, vendors, and government stakeholders.


There are 3 parts to VINCE:

* VINCETrack
* VINCEComm
* VINCEPub

VINCETrack
------------

VINCETrack was designed with the vulnerability coordination team in mind.  It manages tickets, cases, vulnerabilities, contacts, and users.  VINCETrack can have 1 or more coordination teams working..

VINCEComm
-------------

VINCEComm is the collaborative part of the VINCE platform. Vendors and researchers also have access to VINCEComm to communicate about vulnerabilites pre-embargo.  Coordinators decide what to share to each case.

VINCEPub
------------

VINCEPub is the public-facing website for VINCE notifications and advisories.  It also has a vulnerability reporting form for reporters that wish to remain anonymous.

Licensing
------------

VINCE is licensed under a MIT (SEI)-style license.  Please see LICENSE.txt or contact permission@sei.cmu.edu for full terms.


