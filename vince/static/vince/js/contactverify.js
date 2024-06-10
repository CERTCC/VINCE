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

function replaceVendor() {
    var val = $("#id_contact").val();
    var email_body = $("#id_email_body").val();
    email_body = email_body.replace(/\[VENDOR\]/g, val);
    $("#id_email_body").val(email_body);
}

function replaceEmail() {
    var val = $("#id_user").val();
    var	email_body = $("#id_email_body").val();
    email_body = email_body.replace(/\[EMAIL\]/g, val);
    $("#id_email_body").val(email_body);
}

$(document).ready(function() {

    let internal_verification_checkbox = document.getElementById('id_internal');

    function getEmails(e, taggle) {
        if (e) {
            e.preventDefault();
        }
        var contact_id = $("#id_contact").val();
        $.ajax({
            url: "/vince/ajax_calls/contact/"+contact_id,
            success: function(data) {
                taggle.removeAll()
                let emails = data['emails'].split(',');
                taggle.settings.allowedTags = emails
                if (internal_verification_checkbox.checked){
                    taggle.settings.allowedTags.push(document.getElementById('id_user').value)
                }
                for (let i=0; i< emails.length; i++) {
                    taggle.add(emails[i]);
                }
            },
            error: function(){
                console.log("ajax was erroneous")
            },
            complete: function(){
                console.log("ajax was completed")
            }
        });
    }

    let original_email_body = $("#id_email_body").val();
    let internal_verification_email_body = "External verification is not needed because this user's connection to the vendor has been established on the basis of the following evidence:\n\n[JUSTIFICATION]"


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
            select: function( event, ui) { $("#id_contact").val(ui.item.value); getEmails(event, taggle); }
        };
    }

    $(document).on('click', "#customize", function(e) {
        e.preventDefault();
        $("#id_email_body").val(original_email_body);
        replaceVendor();
        replaceEmail();
    });

    $.getJSON("/vince/ajax_calls/search/", function(data) {
	    contact_auto(data);
    });


    $(document).on('submit', "#verifyform", function(e) {
        let $form = $(this);

        if ($form.data('submitted') === true) {
            // Previously submitted - don't submit again
            e.preventDefault();
        } else {
            console.log(1)
            let email_body = $("#id_email_body").val();
            console.log(2)
            if ((email_body.search(/VENDOR/) >= 0)) {
                alert("Please check email text and replace VENDOR placeholder text");
                return false;
            }
            console.log(3)
            if ((email_body.search(/EMAIL/) >= 0)) {
                alert("Please check email text and replace EMAIL placeholder text");
                return false;
            }
            console.log(4)
            if ((email_body.search(/JUSTIFICATION/) >= 0)) {
                alert("Please check email text and replace JUSTIFICATION placeholder text");
                return false;
            }
            console.log(5)
            if (internal_verification_checkbox.checked && taggle.getTagValues().length == 0){
                taggle.add(user_to_verify)
            }
            console.log(6)
            // Mark it so that the next submit can be ignored
            $form.data('submitted', true);
        }

        return true;
    });

    var taggle = null;

    if (document.getElementById("email_tags")) {
        var available_tags = JSON.parse(document.getElementById('emails').textContent);
	    var tags = [];
        taggle =  new Taggle('email_tags', {
            tags: available_tags,
	        hiddenInputName: "email",
	        preserveCase:true,
            duplicateTagClass: 'bounce',
	        allowedTags: available_tags,
            placeholder: ["Verification emails must first be added to contact."],
	    });
    };


    // This is all code for VIN-731. It's commented out because we didn't quite have time to test all possible edge cases before a separate process
    // required us to put out a VINCE release.

    let user_to_verify_field = document.getElementById('id_user');
    let user_to_verify = user_to_verify_field.value;
    let email_field = document.getElementById('email_field');

    function adapt_to_checkbox_status(){
        let currentTags = taggle.getTagValues()
        let currentAllowedTags = taggle.settings.allowedTags
        if (!currentAllowedTags){
            currentAllowedTags = []
        }
        if (internal_verification_checkbox.checked){
            if (user_to_verify){
                currentAllowedTags.push(user_to_verify)
                taggle.settings.allowedTags = currentAllowedTags
                taggle.add(user_to_verify)
            }
            email_field.style.display = "none";
            $("#customize").css("visibility", "hidden")
            $("#id_email_body").val(internal_verification_email_body);
        } else {
            if (user_to_verify){
                for (let i=0; i < currentAllowedTags.length; i++){
                    if (currentAllowedTags[i] == user_to_verify){
                        currentAllowedTags.splice(i, 1)
                    }
                }
                taggle.settings.allowedTags = currentAllowedTags
                for (let i=0; i< currentTags.length; i++) {
                    if (currentTags[i] == user_to_verify) {
                        taggle.remove(currentTags[i])
                    }
                }
            }
            email_field.style.display = "initial";
            $("#customize").css("visibility", "visible")
            $("#id_email_body").val(original_email_body);
        };
        if (taggle.settings.allowedTags.length == 0){
            taggle.settings.allowedTags = [''];
        };
    }

    adapt_to_checkbox_status()

    internal_verification_checkbox.addEventListener('change', function() {
        adapt_to_checkbox_status()
    });

    user_to_verify_field.addEventListener('change', function() {
        // remove whatever email was previously allowed as a result of this event listener:
        let currently_allowed_emails = taggle.settings.allowedTags
        if (!currently_allowed_emails){
            currently_allowed_emails = []
        }
        for (let i=0; i < currently_allowed_emails.length; i++){
            if (currently_allowed_emails[i] == user_to_verify){
                currently_allowed_emails.splice(i,1)
                taggle.remove(user_to_verify)
            }
        }
        // allow the new email and add it to the list of taggles:
        user_to_verify = user_to_verify_field.value
        if (internal_verification_checkbox.checked){
            if (user_to_verify){
                currently_allowed_emails.push(user_to_verify)
                taggle.settings.allowedTags = currently_allowed_emails;
                taggle.add(user_to_verify);
            }
        }
    });


});
