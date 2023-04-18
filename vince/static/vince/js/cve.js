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

function change_org(value){
    /* Something with the forms required onChange to be called from the form initialization itself.
    This was to be able to access the proper elements of a row when returning to an existing cve. */
    retval = '#' + value.id
    org_auto(retval, false)
}

function complete_prod(orgid, row_id, prod_input, item_found){
    clear_row(row_id)
    if (item_found.val()){
	let org_url = $('.cveproduct').data('prod-autocomplete');
	prod_input.autocomplete({
	    source: function(request,response) {
		$.getJSON(org_url,{term:request.term})
		    .done(function(data) {
			if("products" in data)
			    response(data.products);
			else
			    response([]);
		    });
	    },
	    disabled: false,
	    minLength: 2,
	    select: function( event, ui) { 
		prod_input.val(ui.item.value); 
		$('#newprod_indicator_'+row_id).html('');
	    }
	});
	
	$(prod_input[0]).on("input propertychange paste", function(){
	    if ($(this).data('val')!=this.value && item_found.val()) {
		if (this.value.length === 0){
		    $('#newprod_indicator_'+row_id).html('');
		}else{
		    $('#newprod_indicator_'+row_id).html('New Product');
		}
	    }
	    $(this).data('val', this.value);	
	});
    }else {
	prod_input.autocomplete({
	    disabled: true
	});
    }
}

function org_auto(item, init) {
    const regex = /[0-9]+/g;
    let item_found = ''
    let prod_input = ''
    let orgid = ''
    if(item){
	orgid = $(item).val();
    }
    if (item && init == true) {
	/* new row in form */
	prod_input = $("#id_product-"+item[0].id.match(regex)[0]+"-cve_affected_product")
	item_found = $("#id_product-"+item[0].id.match(regex)[0]+"-organization")
    } else if (item && init == false){
	/* came back to form after submit or after clearing an organization selection  */
	let row_id =  $(item)[0].id.match(regex)[0]
	prod_input = $("#id_product-"+item.match(regex)[0]+"-cve_affected_product")
	item_found = $("#id_product-"+row_id+"-organization")
	complete_prod(orgid, $(item)[0].id.match(regex)[0], prod_input, item_found)		
    } else {
	/* new form */
	prod_input = $('#id_product-0-cve_affected_product')
	item_found = $('#id_product-0-organization')
    }
    const row_id = item_found[0].id.match(regex)[0]
    prod_input.parent().append('<div id=newprod_indicator_'+row_id+' style="color:red;font-size:14px"></div>')
    
    $(item_found).change(function() {
	if (item_found.val()){
	    complete_prod(orgid, row_id, prod_input, item_found)
	}
    });
}

function clear_row(row_id) {
    selected = false
    $('#newprod_indicator_'+row_id).html('');
    document.getElementById('id_product-'+row_id+'-cve_affected_product').value = "";
    document.getElementById('id_product-'+row_id+'-version_value').value = "";
    document.getElementById('id_product-'+row_id+'-version_affected').value = "None";
    document.getElementById('id_product-'+row_id+'-version_name').value = "";
}

$(document).ready(function() {	
    function post_add_cwe_row(row) {
	row.find("input[id*=cwe]").each(function() {
	    cwe_auto($(this));
	});
    }

    function post_add_org_name(row) {
	row.find("input[id*=product]").each(function() {
	    org_auto($(this), true);
	});
	row.find("select[id*=organization]").trigger("change");
    }

    $("#id_date_public").datepicker({dateFormat: 'yy-mm-dd'});
    $("#id_date_added").datepicker({dateFormat: 'yy-mm-dd'});
    
    function cwe_auto(item) {
	if (item) {
	    var cwe_input=item;
	} else {
	    var cwe_input = $('#id_cwe-0-cwe');
	}
	let cwe_url = $('#cweprefix').data('cwe-url');
	cwe_input.autocomplete({
	    source: cwe_url,
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

    cwe_auto(null);
    org_auto(null, true);
});
