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

function nextPage(page) {
    $("#searchresults").load("/vuls/results/?page=" + page);
}


function reloadSearch() {
    $.ajax({
        url: "/vuls/results/",
        success: function(data) {
            $("#searchresults").html(data);
        }
    });


}

function nextNotes(page) {
    var url = "/vuls/results/";
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

function searchNotes(e) {
    if (e) {
	e.preventDefault();
    }
    $("#id_page").val("1");
    var url = "/vuls/results/";
    $("#searchresults").css({opacity: 0.5});
    $.ajax({
	url: url,
	type: "POST",
	data: $('#searchform').serialize(),
	success: function(data) {
	    $("#searchresults").html(data).css({opacity: 1});
	}
    });
}

$(document).ready(function() {

    function vend_auto(data) {
       var vendor_input=$('#id_vendor');
       vendor_input.autocomplete({
           source: data,
           minLength: 2,
           select: function( event, ui) {
	       $("#id_vendor").val(ui.item.value);
	       searchNotes();
	   },
	   response: function(event, ui) {
	       $('#noresults_vendor').remove();
	       if (ui.content.length === 0) {
		   console.log("No results");
		   if($('#noresults_vendor').length == 0) 
		       $('#id_vendor').after('<h4 id="noresults_vendor" style="color:#dc3545 "> No matches found </h4>');
	       }
	   }
     });
    }

/*    var input = document.getElementById("id_wordSearch");
    input.addEventListener("keyup", function(event) {
	event.preventDefault();
	if (event.keyCode === 13) {
	    event.preventDefault();
	    searchNotes(event);
	}
    });*/

    $(document).on("click", '.search_page', function(event) {
	var page = $(this).attr('next');
	nextPage(page);
    });

    $(document).on("click", '.search_notes', function(event) {
	var page = $(this).attr('next');
	nextNotes(page);
    });
    
    var input = document.getElementById("id_wordSearch");
    input.addEventListener("keyup", function(event) {
        searchNotes(event);
    });

    var form = document.getElementById('searchform');
    if (form.attachEvent) {
	form.attachEvent("submit", searchNotes);
    } else {
	form.addEventListener("submit", searchNotes);
    }

    $("input[id^='id_years_']").change(function() {
	searchNotes();
    });

    searchNotes();

    $.getJSON("/vuls/ajax_calls/search/", function(data) {
        vend_auto(data);
    });

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
	    searchNotes();
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
	    searchNotes();
	});

    $('#moreYear').click(function(e) {
	$("#hideyears").toggle();

	$("#moreYears").toggle();
	$("#lessYears").toggle();
	e.preventDefault();

    });

     $('#lessYear').click(function(e) {
        $("#hideyears").toggle();
        $("#moreYears").toggle();
        $("#lessYears").toggle();
        e.preventDefault();

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
