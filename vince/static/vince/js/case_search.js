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

function nextPage(page) {
    $("#searchresults").load("/vince/case/results/?page=" + page);
}


function reloadSearch() {
    $.ajax({
        url: "/vince/case/results/",
        success: function(data) {
            $("#searchresults").html(data);
        }
    });
}

function nextTickets(page) {
    var url = "/vince/case/results/";
    $("#id_page").val(page);
    $.ajax({
        url: url,
        type: "POST",
        data: $('#searchform').serialize(),
        success: function(data) {
            $("#searchresults").html(data);
        }
    });

}

var txhr = null;

function searchTickets(e) {
    if (e) {
	e.preventDefault();
    }
    $("#id_page").val("1");
    var url = "/vince/case/results/";
    if(txhr && 'abort' in txhr) {
        txhr.abort();
    }
    lockunlock(true,'div.mainbody,div.vtmainbody','#searchresults');
    txhr = $.ajax({
	url: url,
	type: "POST",
	data: $('#searchform').serialize(),
	success: function(data) {
	    lockunlock(false,'div.mainbody,div.vtmainbody','#searchresults');
 	    $("#searchresults").html(data);
	},
	error: function() {
	    lockunlock(false,'div.mainbody,div.vtmainbody','#searchresults');
	    console.log(arguments);
	    alert("Search failed or canceled! See console log for details.");
	},
	complete: function() {
	    /* Just safety net */
	    lockunlock(false,'div.mainbody,div.vtmainbody','#searchresults');
	    window.txhr = null;
 	}
     });
}

$(document).ready(function() {
    
    $(document).on("click", '.search_page', function(event) {
	var page = $(this).attr('next');
	nextPage(page);
    });

    $(document).on("click", '.search_notes', function(event) {
	var page = $(this).attr('next');
	nextTickets(page);
    });
    
    var input = document.getElementById("id_wordSearch");
    input.addEventListener("keydown", function(event) {
	if (event.keyCode == 13) {
            searchTickets(event);
	}
    });

    var form = document.getElementById('searchform');
    if (form.attachEvent) {
	form.attachEvent("submit", searchTickets);
    } else {
	form.addEventListener("submit", searchTickets);
    };

    $('#changes_to_publish').on('click',function() {
	/* If a Case is Updated (updates requiring a re-publish) it is assumed
	   it has already been Published first. The status=2 is Published search */
	if($('#changes_to_publish').prop('checked'))
	    $('#id_status_2').prop('checked',true);
	searchTickets();
    });

    $("#filter_by_dropdown_select_all_0").click(function(){
        $("#id_status input[type=checkbox]").prop('checked', $(this).prop('checked'));
        searchTickets();
    });

    $("#filter_by_dropdown_select_all_1").click(function(){
        $("#id_owner input[type=checkbox]").prop('checked', $(this).prop('checked'));
        searchTickets();
    });

    $("#filter_by_dropdown_select_all_3").click(function(){
        $("#id_team input[type=checkbox]").prop('checked', $(this).prop('checked'));
        searchTickets();
    });
    
    $("input[id^='id_status_']").change(function() {
	searchTickets();
    });

    $("#id_queue").change(function() {
	searchTickets();
    });

    $("#id_case").change(function() {
	searchTickets();
    });

    $("#id_team").change(function() {
        searchTickets();
    });
    
    $("input[id^='id_owner_']").change(function() {
	searchTickets();
    });


    $(document).on("click", '.removestatus', function(event) {
        event.preventDefault();
        var val = $(this).attr("val");
        $("#id_status input[value="+val+"]").prop('checked', false);
        searchTickets();
    });

    $(document).on("click", '.removeowner', function(event) {
        event.preventDefault();
	var val = $(this).attr("val");
        $("#id_owner input[value="+val+"]").prop('checked', false);
        searchTickets();
    });

    $(document).on("click", '.removeteam', function(event) {
        event.preventDefault();
        var val = $(this).attr("val");
        $("#id_team input[value="+val+"]").prop('checked', false);
	searchTickets();
    });

    $(document).on("click",'.removechanges_to_publish', function(event) {
	$('#changes_to_publish').prop('checked',false);
	searchTickets();
    });
    
    searchTickets();

    /*$.getJSON("/vuls/ajax_calls/search/", function(data) {
        vend_auto(data);
    });*/

    var dateFormat = "yy-mm-dd",
        from = $( "#id_datestart" )
        .datepicker({
          defaultDate: "+1w",
          changeMonth: true,
          changeYear: true,
          dateFormat: dateFormat,
          numberOfMonths: 1,
          maxDate: "+0D"
         })
        .on( "change", function() {
            /*to.datepicker( "option", "minDate", getDate( this ) );*/
	    searchTickets();
        }),
	to = $( "#id_dateend" ).datepicker({
            defaultDate: "+1w",
            changeMonth: true,
            changeYear: true,
            dateFormat: dateFormat,
            numberOfMonths: 1,
            maxDate: "+0D"

	})
	.on( "change", function() {
            from.datepicker( "option", "maxDate", getDate( this ) );
	    searchTickets();
	});


    $('input').qtip({
        show: {
            ready: true
        },
          content: {
              attr: 'errormsg'
          },
        position: {
            my: 'top center',
            at: 'top center',
            target: this
        },
        style: {
            classes: 'qtip-red qtip-bootstrap'
        }

    });

    function getDate( element ) {
	var date;
	try {
            date = $.datepicker.parseDate( dateFormat, element.value );
	} catch( error ) {
            date = null;
	}

	return date;
    }
});
