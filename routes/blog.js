const { Router } = require('express');
const multer = require('multer');
const path = require('path');

const Blog = require('../models/blog');
const { title } = require('process');
const Comment = require('../models/comment');

const router = Router();

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.resolve(`./public/uploads`));
    },
    filename: function (req, file, cb) {
        const filename = `${Date.now()}-${file.originalname}`;
        cb(null, filename);
    }
});

const upload = multer({ storage: storage })



router.get('/add-new', (req, res) => {
    res.render('addBlog', {
        user: req.user,
    });
});

router.get('/:id' , async (req, res) => {
    const blog = await Blog.findById(req.params.id).populate("createdBy");
    const comments = await Comment.find({blogId: req.params.id}).populate("createdBy");

    
    return res.render('blog' , {
        user: req.user, 
        blog: blog,
        comments: comments,
    })
});

router.post('/comment/:blogId', async (req, res) => {
    const comment = await Comment.create({
        content: req.body.content,
        blogId: req.params.blogId,
        createdBy: req.user._id,
    });
    return res.redirect(`/blog/${req.params.blogId}`)
})

router.post('/',upload.single('coverImage'),async (req, res) => {
    const blog = await Blog.create({
        title: req.body.title, 
        body: req.body.body, 
        coverImageURL: `/uploads/${req.file.filename}`,
        createdBy: req.user._id, 
    })
    
    return res.redirect(`/blog/${blog._id}`);

});


module.exports = router;