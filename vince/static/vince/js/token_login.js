/*#########################################################################
# VINCE
#
# Copyright 2023 Carnegie Mellon University.
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
function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

$(document).ready(function() {
    var myStorage = window.localStorage;
    var access_token = myStorage.getItem('access_token');
    var refresh_token = myStorage.getItem('refresh_token');
    if (access_token && refresh_token) {
	var url = "/vince/token/login/";
	$.ajax({
	    url: url,
	    type:"POST",
	    data: {'csrfmiddlewaretoken': getCookie('csrftoken'),
		   'access_token': myStorage.getItem('access_token'),
		   'refresh_token':	myStorage.getItem('refresh_token')},
	    success: function(data) {
		const urlParams = new URLSearchParams(window.location.search);
		const nextparam = urlParams.get('next');
		if (nextparam) {
		    window.location.href=nextparam;
		} else {
		    window.location.href="/vince/dashboard/";
		}
	    }
	});
	
    }


 
    

});
