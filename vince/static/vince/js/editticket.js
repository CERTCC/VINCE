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

    $( "#id_due_date" ).datepicker({dateFormat: 'yy-mm-dd', minDate: 0});

    function case_auto(data) {
       var case_input=$('input[id="id_case"]');
       case_input.autocomplete({
        source: data,
        minLength: 2,
           select: function( event, ui) { $("#id_case").val(ui.item.value); }

     });
    }

    
    $.getJSON("/vince/ajax_calls/casesearch/", function(data) {
        case_auto(data);
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
					
    $.getJSON("/vince/ajax_calls/search/", function(data) {
	contact_auto(data);
    });

    $('.contact-formset').formset({
        prefix: $("#contact_formset_prefix").attr("value"),
        addText: 'add contact',
        deleteText: '',
        formCssClass: 'dynamic-formset',
        deleteCssClass: 'remove-formset',
	added: contact_auto()
    });


    
});
