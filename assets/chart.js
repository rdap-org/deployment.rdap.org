function drawCharts(mapData, statsData) {

  let c1, c2;

  if (window.matchMedia && true === window.matchMedia("(prefers-color-scheme: dark)").matches) {
    c1 = '#666';
    c2 = '#393';

  } else {
    c1 = '#eee';
    c2 = '#080';

  }

  google.charts.load('current', {'packages':['corechart', 'geochart']});

  google.charts.setOnLoadCallback(function() {
    const map = new google.visualization.GeoChart(document.getElementById('world-map'));

    map.draw(
      google.visualization.arrayToDataTable(mapData),
      {
        title:            'Deployment of RDAP among ccTLDs',
        legend:           'none',
        colorAxis:        {'colors': [c1, c2]},
        backgroundColor:  {fill:'transparent'},
      }
    );

    const categories = ['all', 'generic', 'country-code'];

    for (var i = 0 ; i < categories.length ; i++) {
      const category  = categories[i];
      const data      = google.visualization.arrayToDataTable(statsData[category]);
      const chart     = new google.visualization.PieChart(document.getElementById(category + '-chart'));

      chart.draw(
        data,
        {
          legend:           'none',
          backgroundColor:  {fill:'transparent'},
          pieSliceText:     'label',
          slices: {
            0: { 'color': c1 },
            1: { 'color': c2 },
          },
        }
      );
    }
  });
}
