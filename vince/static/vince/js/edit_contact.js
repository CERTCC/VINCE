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
function generateVendor(url) {

    $.ajax({
	url: url,
	success: function(data) {
	    $("#id_lotus_id").val(data.id);
	}});
    
}

function post_add_email_row(row) {
    row.find($("input[id*=status]")).each(function() {
	$(this).attr('checked', true);
    });
}


function validateForm() {
    if ($('#id_active').is(":checked")) {
        if (document.forms["cmgr"]["email-0-email"]) {
            var x = $("#id-email-0-email").val();
            if (x == "") {
		alert("Are you sure you want to submit without an email?\n If so, you must mark this contact INACTIVE.");
		return false;
            } else {
		var n = $("#id-email-0-name").val();
		if (n == "") {
                    alert("Name is required with email.");
                    return false;
		}
            }
        } else {
	    alert(document.forms["cmgr"]["email-0-email"]);
           alert("Are you sure you want to submit without an email?\n If so, you must mark this contact INACTIVE.");
            return false;
        }
    }
    return true;
    
}

$(document).ready(function() {

    $(document).on("submit", "#cmgrform", function(event) {
	var $form = $(this);
	var ret = validateForm();
	if (ret == true) {
            if ($form.data('submitted') === true) {
		// Previously submitted - don't submit again                                                                                                                                  
		event.preventDefault();
            } else {
		// Mark it so that the next submit can be ignored                                                                                                                             
		$form.data('submitted', true);
		$("#submitbutton").disabled = true;
		$("#submitbutton").html("Please wait...");

            }
	}
	return ret;
    });

    $(document).on("click", "#generateVendor", function(event) {
	event.preventDefault();
	generateVendor($(this).attr("href"));
    });

    $('.email-formset').formset({
	prefix: $("#email_formset_prefix").attr("value"),
	addText: 'add email',
	deleteText: '',
	formCssClass: 'dynamic-formset6',
	deleteCssClass: 'remove-formset',
	added: post_add_email_row,
    });
    
    $('.postal-formset').formset({
	prefix: $("#postal_formset_prefix").attr("value"),
	addText: 'add address',
	deleteText: '',
        formCssClass: 'dynamic-formset1',
        deleteCssClass: 'remove-address'
    });
    
    $('.phone-formset').formset({
	prefix: $("#phone_formset_prefix").attr("value"),
        addText: 'add phone number',
        deleteText: '',
        formCssClass: 'dynamic-formset2',
        deleteCssClass: 'remove-phone'
    });
    
    $('.web-formset').formset({
	prefix: $("#web_formset_prefix").attr("value"),
        addText: 'add website',
        deleteText: '',
        formCssClass: 'dynamic-formset4',
        deleteCssClass: 'remove-website'
    });
    
    $('.pgp-formset').formset({
	prefix: $("#pgp_formset_prefix").attr("value"),
        addText: 'add key',
        deleteText: '',
        formCssClass: 'dynamic-formset5',
        deleteCssClass: 'remove-address',
        keepFieldValues: '#id_pgp-0-pgp_protocol'
    });
    
});
