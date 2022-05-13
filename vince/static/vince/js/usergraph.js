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


function removeData(chart) {
    chart.data.labels.pop();
    chart.data.datasets.forEach((dataset) => {
        dataset.data.pop();
    });
    chart.update();
}

function addData(chart, data) {
    chart.config.data = data;
    chart.update();
}


$(document).ready(function() {


    $(document).on("click", "#download", function(event) {
	const title = ["Date", "Users", "Vendors", "Cumulative Users", "Cumulative Vendors"];
	var jsonarray = [];
        var lineArray=[];

	jsonarray.push(title)
	old_tags.forEach(function(rowArray, index) {
	    jsonarray.push([rowArray["label"], rowArray["c"], vendors[index]["c"], cum_users[index]["c"], cum_vendors[index]["c"]])
	});
	console.log(jsonarray);
        jsonarray.forEach(function(rowArray, index){
          var line = rowArray.join(",");
          lineArray.push(index == 0 ? "data:text/csv;charset=utf-8," + line : line);
         });
        var csvContent = lineArray.join("\n");
        var anchor = $(this);
        var encodedUri = encodeURI(csvContent);
        window.open(encodedUri);
    });


    
    $(document).on("click", "#reset1", function(event) {
	event.preventDefault();
	removeData(myChart);
	var dataset = {
        datasets: [{
            label: 'Registered Users',
            backgroundColor: 'rgb(255, 99, 132)',
            borderColor: 'rgb(255, 99, 132)',
            data: old_tags.map(o=>({x: o.label, y: Number(o.c)}))
        },
        {
            label: 'Vendor Registrations',
            backgroundColor: "rgba(0, 255, 0, 1)",
            borderColor: "rgba(0, 255, 0, 1)",
            data: vendors.map(o=>({x: o.label, y: Number(o.c)}))
        }],
    };
	addData(myChart, dataset);
	removeData(cumulativeChart);
	var otherdataset = {
            datasets: [{
		label: 'Registered Users',
		backgroundColor: 'rgb(255, 99, 132)',
		borderColor: 'rgb(255, 99, 132)',
                data: cum_users.map(o=>({x: o.label, y: Number(o.c)}))
            },
		       {
			   label: 'Vendor Registrations',
			   backgroundColor: "rgba(0, 255, 0, 1)",
			   borderColor: "rgba(0, 255, 0, 1)",
			   data: cum_vendors.map(o=>({x: o.label, y: Number(o.c)}))
		       }],
	};
	addData(cumulativeChart, otherdataset);
	
    });
    
    function graphClickEvent(event, array) {
	if (array.length > 0) {
	    var index = array[0]["index"];
	    console.log(old_tags[index]["label"]);
	    var csrftoken = getCookie('csrftoken');
	    var url = "/vince/reports/users/";
	    $.post(url,
		   {'csrfmiddlewaretoken': csrftoken, 'month': old_tags[index]["label"]}, function(data) {
		       removeData(myChart);
		       var newdata = {
			   datasets: [{
			       label: 'Registered Users',
			       backgroundColor: 'rgb(255, 99, 132)',
			       borderColor: 'rgb(255, 99, 132)',
			       data: data["users"].map(o=>({x: o.label, y: Number(o.c)}))
			   },
         			      {
					  label: 'Vendor Registrations',
					  backgroundColor: "rgba(0, 255, 0, 1)",
					  borderColor: "rgba(0, 255, 0, 1)",
					  data: data["vendors"].map(o=>({x: o.label, y: Number(o.c)}))
				      }]
		       };
		       addData(myChart, newdata);
		       
		   })
		.fail(function (data) {
		    console.log(data);
		    
		})
	} else {
	    alert("No registrations available for this month.");
	}
    }


    function graphClickEvent2(event, array) {
	if (array.length > 0) {
            var index = array[0]["index"];
            var csrftoken = getCookie('csrftoken');
            var url = "/vince/reports/users/";
            $.post(url,
		   {'csrfmiddlewaretoken': csrftoken, 'month': old_tags[index]["label"]}, function(data) {
                       removeData(cumulativeChart);
		       var newdata = {
			   datasets: [{
			       label: 'Registered Users',
			       backgroundColor: 'rgb(255, 99, 132)',
			       borderColor: 'rgb(255, 99, 132)',
			       data: data["cumusers"].map(o=>({x: o.label, y: Number(o.c)}))
			   },
				      {
					  label: 'Vendor Registrations',
					  backgroundColor: "rgba(0, 255, 0, 1)",
					  borderColor: "rgba(0, 255, 0, 1)",
					  data: data["vendorscum"].map(o=>({x: o.label, y: Number(o.c)}))
				      }],
			   
		       };
		       addData(cumulativeChart, newdata);
		       
		   })
		.fail(function (data) {
		    console.log(data);
		    
		})
	} else {
	    alert("No registrations for this month.");
	}
    }
	    
    
    var options = {
	onClick: graphClickEvent,
        scales: {
            yAxis: {
                min:0,
                ticks: {
                    beginAtZero: true
                }
            },
            xAxis: {
            }
        }
    };

    var old_tags = JSON.parse(document.getElementById('user_reg').textContent);
    var vendors = JSON.parse(document.getElementById('vendors').textContent);

    var orig_dataset = {
        datasets: [{
            label: 'Registered Users',
            backgroundColor: 'rgb(255, 99, 132)',
            borderColor: 'rgb(255, 99, 132)',
            data: old_tags.map(o=>({x: o.label, y: Number(o.c)}))
        },
        {
            label: 'Vendor Registrations',
            backgroundColor: "rgba(0, 255, 0, 1)",
            borderColor: "rgba(0, 255, 0, 1)",
            data: vendors.map(o=>({x: o.label, y: Number(o.c)}))
        }],
    };
	
    var myChart = new Chart(
	document.getElementById('myChart'),
	{
	    type: 'line',
	    data: orig_dataset,
	    options: options
	}
    );
    
    var cum_users = JSON.parse(document.getElementById('cum_users').textContent);
    var cum_vendors = JSON.parse(document.getElementById('cum_vendors').textContent);

    var cumulativedataset = {
        datasets: [{
	    label: 'Registered Users',
	    backgroundColor: 'rgb(255, 99, 132)',
	    borderColor: 'rgb(255, 99, 132)',
		    data: cum_users.map(o=>({x: o.label, y: Number(o.c)}))
	},
        {
	    label: 'Vendor Registrations',
	    backgroundColor: "rgba(0, 255, 0, 1)",
	    borderColor: "rgba(0, 255, 0, 1)",
	    data: cum_vendors.map(o=>({x: o.label, y: Number(o.c)}))
	}],
    };

    
    const cumulativeChart = new Chart(
	document.getElementById('CumulativeChart'),
	{
	    type: 'line',
	    data: cumulativedataset,
 	    options: {
		onClick:graphClickEvent2,
		scales: {
		    yAxis: {
                        min:0,
			ticks: {
			    beginAtZero: true
			}
		    },
		    xAxis: {
		    }
		}
	    }
	}
    );
    
});
