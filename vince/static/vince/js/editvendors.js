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

    var simplemde = new EasyMDE({element: $("#id_statement")[0],
                                 renderingConfig: {
                                     singleLineBreaks: false,
                                 },
                                 status: false,
                                 autoDownloadFontAwesome: false,
                                });
    
    var simpleadd = new EasyMDE({element: $("#id_addendum")[0],
                                 renderingConfig: {
                                     singleLineBreaks: false,
                                 },
                                 status: false,
                                 autoDownloadFontAwesome: false,
                                });



    
    $('input.check').on('change', function() {
        var c = $(this).attr("class");
        c = c.replace("check ", ".");
        $(c).not(this).prop('checked', false);
    });
    
    var modal = $("#editstatement");
    $(document).on("click", '.editstmt', function(event) {
	event.preventDefault();
	var url = $(this).attr("action");
	$.ajax({
	    url: url,
	    type: "GET",
            success: function(data) {
		modal.html(data).foundation('open');
	    }
	});
    });

    $(document).on("submit", "#providestatementform", function(event) {
	event.preventDefault();
	var $form = $( this );
        var url = $(this).attr( "action" );
        var csrftoken = getCookie('csrftoken');
	var data = $(this).serializeArray();
	var posting = $.post( url, data );

        // Put the results in a div                                                            
        posting.done(function( data ) {
	    location.reload(true);
        });
	modal.html(data).foundation('close');
    });


    $( "#id_statement_date" ).datepicker({dateFormat: 'yy-mm-dd'});


    $(document).on("click", "#select_all_affected", function(event) {
        var status = $(this).is(':checked');
        //$(".checkvendors").prop('checked', status);	
	$(':checkbox[name=unaffected]').prop("checked", false);
	$(':checkbox[name=unknown]').prop("checked", false);
	$(':checkbox[name=affected]').prop("checked", status);
	$(':checkbox[name=notaffected]').prop("checked", false);
	$(':checkbox[name=allunknown]').prop("checked", false);
    });


    $(document).on("click", "#select_all_not", function(event) {
	var status = $(this).is(':checked');
        //$(".checkvendors").prop('checked', status);
	$(':checkbox[name=affected]').prop("checked", false);
	$(':checkbox[name=unknown]').prop("checked", false);
        $(':checkbox[name=unaffected]').prop("checked", status);
	$(':checkbox[name=allaffected]').prop("checked", false);
	$(':checkbox[name=allunknown]').prop("checked", false);
    });

    $(document).on("click", "#select_all_unknown", function(event) {
	var status = $(this).is(':checked');
        //$(".checkvendors").prop('checked', status);
        $(':checkbox[name=unaffected]').prop("checked", false);
	$(':checkbox[name=affected]').prop("checked", false);
        $(':checkbox[name=unknown]').prop("checked", status);
	$(':checkbox[name=notaffected]').prop("checked", false);
	$(':checkbox[name=allaffected]').prop("checked", false);
    });

});
