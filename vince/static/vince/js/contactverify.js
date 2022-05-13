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

function replaceVendor() {
    var val = $("#id_contact").val();
    var email_body = $("#id_email_body").val();
    email_body = email_body.replace(/\[VENDOR\]/g, val);
    console.log(email_body);
    $("#id_email_body").val(email_body);
}

function replaceEmail() {
    var val = $("#id_user").val();
    var	email_body = $("#id_email_body").val();
    email_body = email_body.replace(/\[EMAIL\]/g, val);
    console.log(email_body);
    $("#id_email_body").val(email_body);
}


$(document).ready(function() {


    $('form').on('submit', function (e) {
        var $form = $(this);

        if ($form.data('submitted') === true) {
            // Previously submitted - don't submit again                                                                                     
            e.preventDefault();
        } else {
            // Mark it so that the next submit can be ignored                                                                                
            $form.data('submitted', true);
        }

        return this;
    });
    
    var options = {}
    var selector = 'input[id^=id_contact]'
    $(document).on('keydown.autocomplete', selector, function() {
	$(this).autocomplete(options);
    });
    
    function contact_auto(data) {
	var contact_input=$('input[id^=id_contact]');
	options = {
	    source:data,
	    minLength: 2,
	};
    }

    $(document).on('click', "#customize", function(e) {
	e.preventDefault();
	replaceVendor();
	replaceEmail();
    });

    $.getJSON("/vince/ajax_calls/search/", function(data) {
	contact_auto(data);
    });


    $(document).on('submit', "#verifyform", function(e) {
	var email_body = $("#id_email_body").val();
	
	if ((email_body.search(/VENDOR/) >= 0)) {
	    console.log(email_body.search(/VENDOR/));
	    alert("Please check email text and replace VENDOR placeholder text");
	    return false;
	}
	if ((email_body.search(/EMAIL/) >= 0)) {
	    alert("Please check email text and replace EMAIL placeholder text");
	    return false;
	}

	return true;
    });

    
});
