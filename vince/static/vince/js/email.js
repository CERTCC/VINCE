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

function getEmails(e) {
    if (e) {
	e.preventDefault();
    }

    var contact_id = $("#id_contact").val();
    $.ajax({
	url: "/vince/ajax_calls/contact/"+contact_id,
	success: function(data) {
	    $('#pgp_keys select option').each(function() {
		$(this).remove();
	    });
	    $("#id_to").val(data['emails']);
	    if (data['pgp_key_data']) {
		$("#pgp_keys select").append(
                $('<option />').text(data['pgp'][0])
			.val(data['pgp'][0]));
		$("#id_pgp_key").val(data['pgp_key_data']);
	    } else {
		jQuery.each(data['pgp'], function() {
		    $('<option />', {
			'value': this,
			'text': this
		    }).appendTo("#pgp_keys select");
		});
	    }
	    $("#pgp_key_info tr").remove();
	    $("#pgp_key_info").append("<tr><td><b>Key ID</b></td><td><b>Email</b></td><td><b>Key</b></td><td><b>Start</b></td><td><b>End</b></td></tr>")
	    jQuery.each(data['pgp_key_info'], function() {
		if (this[2]) {
		    $("#pgp_key_info").append("<tr><td>"+this[0]+"</td><td>"+this[1]+"</td><td><b>YES</b></td><td>"+this[3]+"</td><td>"+this[4]+"</td></tr>");
		} else {
		    $("#pgp_key_info").append("<tr><td>"+this[0]+"</td><td>"+this[1]+"</td><td><b>NO KEY</b></td></tr>");
		}
	    });
	}
    });
}


function Removefile(event) {
    event.preventDefault();
    var input = $("#file-title-wrap");
    input.replaceWith(input.val('').clone(true));
    $("#file-title-wrap").hide();

}


function onBeforeUnload(e) {
    e.preventDefault();
    e.returnValue = '';
    return;
}

$(document).ready(function() {


    window.addEventListener('beforeunload', onBeforeUnload);

    $('form').submit(function () {
        window.removeEventListener('beforeunload', onBeforeUnload);
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
	    select: function( event, ui) { $("#id_contact").val(ui.item.value); getEmails(); }
        };
    }

    function case_auto(data) {
       var case_input=$('input[id="id_case"]');
       case_input.autocomplete({
        source: data,
        minLength: 2,
           select: function( event, ui) { $("#id_case").val(ui.item.value); }

     });
    }

    /* get select value */
    var email_type = $("#id_email_type").val();
    if (email_type == 2) {
	$('#pgp_key_email').toggle(true);
        $('#pgp_keys').toggle(true);
    }
    

    $.getJSON("/vince/ajax_calls/casesearch/", function(data) {
        case_auto(data);
    });

    
    $.getJSON("/vince/ajax_calls/search/nogroup/", function(data) {
        contact_auto(data);
    });


    $(document).on("change", "#id_email_type", function(event) {
        var showOrHide = ($(this).val() == 2) ? true : false;
        $('#pgp_key_email').toggle(showOrHide);
	$('#pgp_keys').toggle(showOrHide);
	if (showOrHide) {
	    if ($('input[id^=id_contact]').val()) {
		getEmails();
	    }
	}
	showOrHide = ($(this).val() == 3) ? true : false;
        $('.certificate_email').toggle(showOrHide);	
    });

    $(document).on("change", "#pgp_keys select", function(event) {
	var count = $(this).val().length;
	if (count > 1) {
	    $("#pgp_key_email").toggle(false);
	} else {
	    $("#pgp_key_email").toggle(true);
	    $.ajax({
		url: "/vince/ajax_calls/pgp/"+$(this).val(),
		success: function(data) {
		    $("#id_pgp_key").val(data);
		}
	    });
	}
    });

    $(document).on("change", "#id_email_template", function() {
        $.ajax({
            url: "/vince/api/template/"+$(this).val()+"/",
            type: "GET",
            success: function(data) {
                $("#id_email_body").val(data['body']);
		$("#id_subject").val(data['subject']);
            }
        });
    });


    $(document).on("change", "#id_new_certificate", function(event) {
	var input = $(this).val();
        var filename = input.replace(/^.*[\\\/]/, '');
        $("#file-title-wrap").html('<p>' + filename +'&nbsp&nbsp<a href="#" class="removefile"><i class="fas fa-times-circle"></i></a></p>');
        $("#file-title-wrap").show();
        if ($("#id_title")) {
            $("#id_title").val(filename);
            $("#id_value").val(filename);
        }
    });    

    $(document).on("click", ".removefile", function(event) {
        Removefile(event);
    });
    
});
