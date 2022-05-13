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
$(document).ready(function() {


    var simplemde = new EasyMDE({element: $("#id_statement")[0],
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
    
    var modal = $("#providestatement");
    $(document).on("click", '.providestatement', function(event) {
	event.preventDefault();
	$.ajax({
	    url: $(this).attr("href"),
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
	    modal.foundation('close');
	    if (data['statement']) {
		$("#stmtbutton"+data['vul_id']).text("Edit Statement");
	    } else {
		$("#stmtbutton"+data['vul_id']).text("Provide Statement");
	    }
        });

    });


    $(document).on("click", "#select_all_affected", function(event) {
	event.preventDefault();
	$('select[name^=status]').val("affected");
    });


    $(document).on("click", "#select_all_notaffected", function(event) {
        event.preventDefault();
        $('select[name^=status]').val("unaffected");
    });

    $(document).on("click", "#select_all_unknown", function(event) {
        event.preventDefault();
        $('select[name^=status]').val("unknown");
    });

});
