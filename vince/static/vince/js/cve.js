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

    function post_add_cwe_row(row) {
	row.find($("input[id*=cwe]")).each(function() {
            cwe_auto($(this));
	});
    }

    $( "#id_date_public" ).datepicker({dateFormat: 'yy-mm-dd'});
    $("#id_date_added").datepicker({dateFormat: 'yy-mm-dd'});
    
    function cwe_auto(item) {
	if (item) {
            var cwe_input=item;
	} else {
	    var cwe_input = $('#id_cwe-0-cwe');
	}
	
	cwe_input.autocomplete({
            source:"/vince/ajax_calls/cwe/",
            minLength: 2,
            select: function( event, ui) { cwe_input.val(ui.item.value); }
	});
    }
    
    $('.cwe_formset').formset({
	prefix: $("#cweprefix").html(),
	deleteText: '',
	addText: '<i class=\'fas fa-plus\'></i> add cwe',
	addCssClass: 'button default small',
	formCssClass: 'cmu-formset1',
	deleteCssClass: 'remove-formset',
	added: post_add_cwe_row,
    });
    
    $('.prod_formset').formset({
	prefix: $("#prodprefix").html(),
	deleteText: '',
	addText: '<i class=\'fas fa-plus\'></i> add product',
	addCssClass: 'button default small',
	formCssClass: 'cmu-formset2',
	deleteCssClass: 'remove-formset right'
    });
    $('.ref_formset').formset({
	prefix: $("#refprefix").html(),
	deleteText: '',
	addText: '<i class=\'fas fa-plus\'></i> add reference',
	addCssClass: 'button default small',
	formCssClass: 'cmu-formset3',
	deleteCssClass: 'remove-formset'
    });
    $('.wa_formset').formset({
	prefix: $("#waprefix").html(),
	deleteText: '',
	addText: '<i class=\'fas fa-plus\'></i> add workaround',
	addCssClass: 'button default small',
	formCssClass: 'cmu-formset4',
	deleteCssClass: 'remove-formset'
    });

    cwe_auto(null);

});
