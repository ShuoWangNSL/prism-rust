svg.append('svg:defs').append('svg:marker')
    .attr('id', 'small-arrow')
    .attr('refX', 6)
    .attr('refY', 3)
    .attr('markerWidth', 12)
    .attr('markerHeight', 12)
    .attr('markerUnits','userSpaceOnUse')
    .attr('orient', 'auto')
    .append('path')
    .attr('d', 'M 0 0 L 6 3 L 0 6')
    .style('stroke', 'white')
    .style('fill', 'none')

let linearGradient = svg.append('defs')
            .append('linearGradient')
            .attr('id', 'linear-gradient')
            .attr('gradientTransform', 'rotate(0)')

linearGradient.append('stop')
    .attr('offset', '0%')
    .attr('stop-color', 'grey')

linearGradient.append('stop')
    .attr('offset', '100%')
    .attr('stop-color', 'white')

let blurFilter = svg.append('svg:defs').append('filter')
    .attr('id','blur')
blurFilter.append('feGaussianBlur')
    .attr('stdDeviation','1')

let glow = (url) => {
    function constructor(svg) {
      let defs = svg.append('defs')
      let filter = defs.append('filter')
          .attr('id', url)
          .attr('x', '-20%')
          .attr('y', '-20%')
          .attr('width', '140%')
          .attr('height', '140%')
        .call(svg => {
          svg.append('feColorMatrix')
              .attr('type', 'matrix')
              .attr('values', colorMatrix)
          svg.append('feGaussianBlur')
               // .attr('in', 'SourceGraphics')
              .attr('stdDeviation', stdDeviation)
              .attr('result', 'coloredBlur')
        })

      filter.append('feMerge')
        .call(svg => {
          svg.append('feMergeNode')
              .attr('in', 'coloredBlur')
          svg.append('feMergeNode')
              .attr('in', 'SourceGraphic')
        })
    }

  constructor.rgb = (value) => {
    rgb = value
    color = d3.rgb(value)
    let matrix = '0 0 0 red 0 0 0 0 0 green 0 0 0 0 blue 0 0 0 1 0'
    colorMatrix = matrix
      .replace('red', color.r)
      .replace('green', color.g)
      .replace('blue', color.b)

    return constructor
  }

  constructor.stdDeviation = (value) => {
    stdDeviation = value
    return constructor
  }

  return constructor
}