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
$(document).ready(function() {

    $('input.check').on('change', function() {
        var c = $(this).attr("class");
        c = c.replace("check ", ".");
        $(c).not(this).prop('checked', false);
    });
    

    $(document).on("click", '.approve', function(event) {
	event.preventDefault();
	var vulid = $(this).attr("vulid");
	var modal = $("#vul"+vulid);
	var csrftoken = getCookie('csrftoken');
	var data = {'vulid': vulid, 'csrfmiddlewaretoken': csrftoken};
	var url = "/vince/vul/"+vulid+"/approve/";
	var posting = $.post( url, data );
	modal.foundation('close');
        // Put the results in a div
        posting.done(function( data ) {
	    location.reload();
        });

    });


    $(document).on("click", '.approveall', function(event) {
        event.preventDefault();
        var vulid = $(this).attr("vendorid");
        var csrftoken = getCookie('csrftoken');
        var data = {'vendor': vulid, 'csrfmiddlewaretoken': csrftoken};
        var url = "/vince/vendor/approve/"+vulid+"/";
        var posting = $.post( url, data );
	var $modal = $('#statusmodal');
        // Put the results in a div
        posting.done(function( data ) {
	    if (document.getElementById('statusmodal')) {
		/* this is when approve is called from case view */
		$modal.foundation('close');
	    } else {
		/*otherwise in vendor status view, reload*/
		location.reload();
	    }
        });

    });
    

});
