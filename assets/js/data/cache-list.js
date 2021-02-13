---
layout: compress

# The list to be cached by PWA
---

const include = [

  /*--- CSS ---*/
  '{{ "/assets/css/style.css" | relative_url }}',

  /*--- Javascripts ---*/
  '{{ "/assets/js/dist/home.min.js" | relative_url }}',
  '{{ "/assets/js/dist/page.min.js" | relative_url }}',
  '{{ "/assets/js/dist/post.min.js" | relative_url }}',
  '{{ "/assets/js/dist/categories.min.js" | relative_url }}',

  /*--- HTML ---*/

  /* Tabs */
  {% for tab in site.tabs %}
    '{{ tab.url }}',
  {% endfor %}

  /*--- Icons ---*/

  {%- capture icon_url -%}
    {{ "/assets/img/favicons" | relative_url }}
  {%- endcapture -%}
  '{{ icon_url }}/favicon.ico',
  '{{ icon_url }}/ms-icon-144x144.png',
  '{{ icon_url }}/manifest.json',
  '{{ icon_url }}/browserconfig.xml',

  /*--- Others ---*/

  '{{ "/assets/js/data/search.json" | relative_url }}',
  '{{ "/404.html" | relative_url }}',

  '{{ "/app.js" | relative_url }}',
  '{{ "/sw.js" | relative_url }}'
];

const exclude = [
  {%- if site.google_analytics.pv.proxy_url and site.google_analytics.pv.enabled -%}
    '{{ site.google_analytics.pv.proxy_url }}',
  {%- endif -%}
  '/assets/js/data/pageviews.json',
  '/img.shields.io/'
];
