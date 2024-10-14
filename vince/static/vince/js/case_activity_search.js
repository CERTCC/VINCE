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

function searchComms(e) {
    if (e) {
        e.preventDefault();
    }
    lockunlock(true,'div.mainbody,div.vtmainbody','#timeline');
    window.txhr = $.ajax({
        url: $("#filterform").attr("action"),
        type: "POST",
        data: $('#filterform').serialize(),
        success: function(data) {
	        lockunlock(false,'div.mainbody,div.vtmainbody','#timeline');
            $("#timeline").html(data);
	        /* reload plugins */
            $(document).foundation();
        },
	    error: function() {
            lockunlock(false,'div.mainbody,div.vtmainbody','#timeline');
            console.log(arguments);
            alert("Search failed or canceled! See console log for details.");
        },
        complete: function() {
            /* Just safety net */
            lockunlock(false,'div.mainbody,div.vtmainbody','#timeline');
	        window.txhr = null;
        }
    });
}

$(document).ready(function() {
    $("input[id^='id_status_']").change(function(event) {
        searchTickets();
    });

    $(".vendorchoice input").change(function(event) {
        searchComms();
    });

    $("#id_timesort").change(function(event) {
        searchComms();
    });


    $("#id_communication_type").change(function(event) {
        searchComms();
    });

    $("#id_participants").change(function(event) {
	searchComms();
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
            searchComms();
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
            searchComms();
        });



    var form = document.getElementById('filterform');
    if (form) {
        if (form.attachEvent) {
            form.attachEvent("submit", searchComms);
        } else {
            form.addEventListener("submit", searchComms);
        }
    }
});