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


function getEmails(e, taggle) {
    if (e) {
        e.preventDefault();
    }
    var contact_id = $("#id_contact").val();
    $.ajax({
        url: "/vince/ajax_calls/contact/"+contact_id,
        success: function(data) {
            taggle.removeAll()
            var emails = data['emails'].split(',');
            taggle.settings.allowedTags = emails
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



$(document).ready(function() {

    var original_email_body = $("#id_email_body").val();

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
        console.log('the data entered into getJSON is');
        console.log(data);
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
            placeholder: ["Verification emails must first be added to contact. If verifying internally, enter the email of the user being verified."]
	    });
    }


    // This is all code for VIN-731. It's commented out because we didn't quite have time to test all possible edge cases before a separate process
    // required us to put out a VINCE release.

    // console.log('taggle is')
    // console.log(taggle)

    // let internal_verification_checkbox = document.getElementById('id_internal');

    // internal_verification_checkbox.addEventListener('change', function() {
    //     let available_tags = JSON.parse(document.getElementById('emails').textContent);
    //     if (available_tags == ''){
    //         available_tags = []
    //     }
    //     let currentTags = taggle.getTagValues()
    //     let email_to_verify = document.getElementById('id_user').value
    //     if (this.checked) {
    //         available_tags.push(email_to_verify)
    //         console.log('available_tags is')
    //         console.log(available_tags)
    //         taggle.settings.allowedTags = available_tags
    //         if (currentTags.length == 0){
    //             taggle.add(email_to_verify)
    //         }
    //     } else {
    //         console.log('available_tags is')
    //         console.log(available_tags)
    //         for (let i=0; i < available_tags.length; i++){
    //             if (available_tags[i] == email_to_verify){
    //                 available_tags.splice(i, 1)
    //             }
    //         }
    //         console.log('after splicing, available_tags is')
    //         console.log(available_tags)
    //         taggle.settings.allowedTags = available_tags
    //         for (let i=0; i< currentTags.length; i++) {
    //             if (currentTags[i] == email_to_verify) {
    //                 taggle.remove(currentTags[i])
    //             }
    //         }
    //     }
    // });

    // let user_to_verify_field = document.getElementById('id_user');

    // let temporarily_allowed_email = ""
    // user_to_verify_field.addEventListener('change', function() {
    //     // remove whatever email was previously allowed as a result of this event listener:
    //     let currently_allowed_emails = taggle.settings.allowedTags
    //     for (let i=0; i < currently_allowed_emails.length; i++){
    //         if (currently_allowed_emails[i] == temporarily_allowed_email){
    //             currently_allowed_emails.splice(i,1)
    //             taggle.remove(temporarily_allowed_email)
    //         }
    //     }
    //     // allow the new email and add it to the list of taggles:
    //     temporarily_allowed_email = user_to_verify_field.value
    //     currently_allowed_emails.push(temporarily_allowed_email)
    //     if (internal_verification_checkbox.checked){
    //         taggle.settings.allowedTags = currently_allowed_emails;
    //         taggle.add(temporarily_allowed_email);
    //     }
    // });


});
