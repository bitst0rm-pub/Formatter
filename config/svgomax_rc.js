module.exports = {
    multipass: true,  // boolean
    datauri: false,  // false|'base64'|'enc'|'unenc'
    js2svg: {
        indent: 4,  // number
        pretty: true  // boolean
    },
    plugins: [
        // 'addAttributesToSVGElement',  // adds attributes to an outer <svg> element
        // 'addClassesToSVGElement',  // adds classnames to an outer <svg> element
        // 'cleanupAttrs',  // cleanups attributes from newlines, trailing and repeating spaces
        // 'cleanupEnableBackground',  // remove or cleanup enable-background attribute when possible
        // 'cleanupIds',  // removes unused IDs and minifies used
        // 'cleanupListOfValues',  // rounds list of values to the fixed precision
        // 'cleanupNumericValues',  // rounds numeric values to the fixed precision, removes default ‘px’ units
        // 'collapseGroups',  // collapses useless groups
        // 'convertColors',  // converts colors: rgb() to #rrggbb and #rrggbb to #rgb
        // 'convertEllipseToCircle',  // converts non-eccentric <ellipse>s to <circle>s
        // 'convertOneStopGradients',  // converts one-stop (single color) gradients to a plain color
        // 'convertPathData',  // optimizes path data: writes in shorter form, applies transformations
        // 'convertShapeToPath',  // converts basic shapes to more compact path form
        // 'convertStyleToAttrs',  // converts style to attributes
        // 'convertTransform',  // collapses multiple transformations and optimizes it
        // 'inlineStyles',  // inline styles (additional options)
        // 'mergePaths',  // merges multiple paths in one if possible
        // 'mergeStyles',  // merge multiple style elements into one
        // 'minifyStyles',  // minifies styles and removes unused styles
        // 'moveElemsAttrsToGroup',  // Move common attributes of group children to the group
        // 'moveGroupAttrsToElems',  // moves some group attributes to the content elements
        'prefixIds',  // enable built-in plugins by name
        'preset-default',  // built-in plugins enabled by default
        // 'removeAttributesBySelector',  // removes attributes of elements that match a css selector
        // 'removeAttrs',  // removes specified attributes
        // 'removeComments',  // removes comments
        // 'removeDesc',  // removes <desc>
        // 'removeDimensions',  // removes width and height in presence of viewBox (opposite to removeViewBox, disable it first)
        // 'removeDoctype',  // removes doctype declaration
        // 'removeEditorsNSData',  // removes editors namespaces, elements and attributes
        // 'removeElementsByAttr',  // removes arbitrary elements by ID or className (disabled by default)
        // 'removeEmptyAttrs',  // removes empty attributes
        // 'removeEmptyContainers',  // removes empty container elements
        // 'removeEmptyText',  // removes empty <text> elements
        // 'removeHiddenElems',  // removes hidden elements (zero sized, with absent attributes)
        // 'removeMetadata',  // removes <metadata>
        // 'removeNonInheritableGroupAttrs',  // removes non-inheritable group’s presentational attributes
        // 'removeOffCanvasPaths',  // removes elements that are drawn outside of the viewbox (disabled by default)
        // 'removeRasterImages',  // removes raster images (disabled by default)
        // 'removeScriptElement',  // removes scripts (disabled by default)
        // 'removeStyleElement',  // removes <style> element (disabled by default)
        // 'removeTitle',  // removes <title>
        // 'removeUnknownsAndDefaults',  // removes unknown elements content and attributes, removes attrs with default values
        // 'removeUnusedNS',  // removes unused namespaces declaration
        // 'removeUselessDefs',  // removes elements in <defs> without id
        // 'removeUselessStrokeAndFill',  // removes useless stroke and fill attributes
        // 'removeViewBox',  // removes viewBox attribute when possible
        // 'removeXlink',  // remove xlink namespace and replaces attributes with the SVG 2 equivalent where applicable
        // 'removeXMLNS',  // removes xmlns attribute (for inline svg, disabled by default)
        // 'removeXMLProcInst',  // removes XML processing instructions
        // 'reusePaths',  // Finds <path> elements with the same d, fill, and stroke, and converts them to <use> elements referencing a single <path> def.
        // 'sortAttrs',  // Sort element attributes for better compression
        // 'sortDefsChildren',  // Sorts children of <defs> to improve compression

        // enable built-in plugins with an object to configure plugins
        {
            name: 'prefixIds',
            params: {
                prefix: 'uwu'
            }
        }
    ]
};
