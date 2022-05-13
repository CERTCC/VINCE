/*#########################################################################
# VINCE
#
# Copyright 2022 Carnegie Mellon University.
#
# NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
# INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
# UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
# AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
# PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE
# MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND
# WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
#
# Released under a MIT (SEI)-style license, please see license.txt or contact
# permission@sei.cmu.edu for full terms.
#
# [DISTRIBUTION STATEMENT A] This material has been approved for public
# release and unlimited distribution.  Please see Copyright notice for non-US
# Government use and distribution.
#
# Carnegie Mellon®, CERT® and CERT Coordination Center® are registered in the
# U.S. Patent and Trademark Office by Carnegie Mellon University.
#
# This Software includes and/or makes use of Third-Party Software each subject
# to its own license.
#
# DM21-1126
########################################################################
*/
/* 3 */
$(document).ready(function() {

    var url = "/vince/tokens/";
    $.ajax({
        url: url,
        success: function(data) {
	    myStorage = window.localStorage;
	    myStorage.setItem('access_token', data['ACCESS_TOKEN']);
	    myStorage.setItem('refresh_token', data['REFRESH_TOKEN']);
	    var url = "/comm/token/login/";
	    $.ajax({
		url: url,
		type:"POST",
		data: {'csrfmiddlewaretoken': getCookie('csrftoken'),
		       'access_token': myStorage.getItem('access_token'),
		       'refresh_token':	myStorage.getItem('refresh_token')},
		success: function(data) {
		    var next_action = $("#next_action").text();
		    if (next_action) {
			window.location.href=next_action;
		    } else {
		      window.location.href="/comm/dashboard/";
		    }
		},
		fail: function(data) {
		    myStorage.removeItem('access_token');
		    myStorage.removeItem('refresh_token');
		    window.location.href="/comm/login/";
		},
		error: function(data) {
		    myStorage.removeItem('refresh_token');
		    myStorage.removeItem('access_token');
		    window.location.href="/comm/login/";
		}
	    });

        }
    });

});
