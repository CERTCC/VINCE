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
function initiate_datepicker(row) {
    $( "#id_exploit-1-reference_date" ).datepicker({dateFormat: 'yy-mm-dd'});
    $( "#id_exploit-2-reference_date" ).datepicker({dateFormat: 'yy-mm-dd'});
    $( "#id_exploit-3-reference_date" ).datepicker({dateFormat: 'yy-mm-dd'});
    $( "#id_exploit-4-reference_date" ).datepicker({dateFormat: 'yy-mm-dd'});

}

function init_vul_tags() {
    console.log("INITIALIZING TAGS");
    var vul_tags = []
    if (document.getElementById('vul_tags')) {
        vul_tags = JSON.parse(document.getElementById('vul_tags').textContent);
    }
    var allowed_tags = JSON.parse(document.getElementById('allowed_tags').textContent);

    console.log(allowed_tags);
    
    var taggle = new Taggle('taggs', {
        tags: vul_tags,
	allowedTags: allowed_tags,
        duplicateTagClass: 'bounce',
        placeholder: ["Tag this vulnerability..."],

    });

    if (allowed_tags.length == 0) {
	taggle.disable();
    }
    
    autoVulTaggle(allowed_tags, taggle);
}

function autoVulTaggle(data, taggle) {
    var container = taggle.getContainer();
    var input = taggle.getInput();
    $(input).autocomplete({
        source: data,
        appendTo:container,
        position: { at: "left bottom", of: container },
        select: function(event, data) {
            event.preventDefault();
            if (event.which === 1) {
                taggle.add(data.item.value);
		add_tag(taggle, data.item.label, null)
            }
        }
    });
}

function initiate_vul_add_form() {


    $( "#id_date_public" ).datepicker({dateFormat: 'yy-mm-dd'});
    
    function post_add_cwe_row(row) {
        row.find($("input[id*=cwe]")).each(function() {
            cwe_auto($(this));
        });
    }

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

    init_vul_tags();

    
    $('.cwe_formset').formset({
        prefix: $("#cwe_formset").attr("prefix"),
        addText: '<i class=\'fas fa-plus\'></i> add cwe',
        deleteText: '',
        addCssClass: 'button primary tiny',
        /*formCssClass: 'dynamic-formset',*/
        deleteCssClass: 'remove-formset right',
	added: post_add_cwe_row
    });
    cwe_auto(null);


    $( "#id_exploit-0-reference_date" ).datepicker({dateFormat: 'yy-mm-dd'});
    $( "#id_exploit-1-reference_date" ).datepicker({dateFormat: 'yy-mm-dd'});
    $( "#id_exploit-2-reference_date" ).datepicker({dateFormat: 'yy-mm-dd'});
    $( "#id_exploit-3-reference_date" ).datepicker({dateFormat: 'yy-mm-dd'});
    $( "#id_exploit-4-reference_date" ).datepicker({dateFormat: 'yy-mm-dd'});

    var exploit_formset = $('.exploit_formset').length;
    if (exploit_formset) {
        $('.exploit_formset').formset({
            prefix: 'exploit',
            deleteText: '',
            addText: '<i class=\'fas fa-plus\'></i> add exploit',
            addCssClass: 'button primary tiny',
            /*formCssClass: 'dynamic-formset',*/
            deleteCssClass: 'remove-formset right',
	    added: initiate_datepicker,
	    
        });
    }
    
    var ref_formset = $('.ref_formset').length;
    if (ref_formset) {
        $('.ref_formset').formset({
            prefix: 'ref',
            deleteText: '',
            addText: '<i class=\'fas fa-plus\'></i> add reference',
            addCssClass: 'button tiny primary',
            /*formCssClass: 'dynamic-formset',*/
            deleteCssClass: 'remove-formset right'
        });
    }
    

}
