/*
  #########################################################################
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

function org_change(event) {
    
$(el).closest('tr').find('.organization')    
    $(el).closest('tr').find('.organization')
    let org = event.target;
}

function org_auto(item) {
    if (!item) {
	item = $('.affected_product').not('.ui-autocomplete-input');
    }
    item.closest('tr').find('.organization').on("change",function() {
	/* Clear all elements in the row on organization change */
	$(this).closest('tr').find("input").val('');
	$(this).closest('tr').find(".range_type")
	    .prop('selectedIndex',0);
    });
    let base_url = $('.cveproduct').data('prod-autocomplete');    
    item.autocomplete({
	source: function(request,response) {
	    let el = this.element;
	    let org_id = $(el).closest('tr').find('.organization').val();
	    if(org_id) {
		let org_url = base_url + org_id + '/';
		$.getJSON(org_url,{term:request.term})
		    .done(function(data) {
			if("products" in data)
			    response(data.products);
			else
			    response([]);
		    });
	    } else {
		response([]);
	    }
	},
	disabled: false,
	minLength: 2,
	change: function(event, ui) {
	    if(!ui.item)
		$(event.target).after($("<small>")
				      .addClass("required rnew")
				      .html("** New Product **"));
	    else
		$(event.target).parent().find(".rnew").remove();
	}	
    });
}

$(document).ready(function() {	
    function post_add_cwe_row(row) {
	cwe_auto(row.find("input"));
    }

    function post_add_org_name(row) {
	org_auto(row.find(".affected_product"));
    }

    $("#id_date_public").datepicker({dateFormat: 'yy-mm-dd'});
    $("#id_date_added").datepicker({dateFormat: 'yy-mm-dd'});
    
    function cwe_auto(item) {
	if (!item) {
	    item = $('.cwe').not('.ui-autocomplete-input');
	}
	let cwe_url = $('#cweprefix').data('cwe-url');
	$.getJSON(cwe_url).done(function(data) {
	    item.autocomplete({
		source: data,
		minLength: 2
	    });
	});
    }
    
    $('.cwe_formset').formset({
	prefix: $("#cweprefix").html(),
	deleteText: '',
	addText: '<i class=\'fas fa-plus\'></i> add cwe',
	addCssClass: 'button default small',
	formCssClass: 'cmu-formset1',
	deleteCssClass: 'remove-formset',
	added: (post_add_cwe_row),
    });
    
    $('.prod_formset').formset({
	prefix: $("#prodprefix").html(),
	deleteText: '',
	addText: '<i class=\'fas fa-plus\'></i> add product to cve',
	addCssClass: 'button default small',
	formCssClass: 'cmu-formset2',
	deleteCssClass: 'remove-formset right',
	added: (post_add_org_name),
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
    /* Run autocomplete on relevatn fields  */
    cwe_auto();
    org_auto();
});
