using Asp.Versioning;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Mohamad.ToDo.Api.Data;
using Mohamad.ToDo.Api.Model;

namespace Mohamad.ToDo.Api.Controllers
{
    [ApiVersion(1)]
    [ApiVersion(2)]
    [Route("api/v{v:apiVersion}/todo")] // http://localhost:5000/api/v1/todo
    //[Route("api/[controller]")] // http://localhost:5000/api/todo
    [ApiController]
    //[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class ToDoController(ApiDbContext context) : ControllerBase
    {
        [MapToApiVersion(2)]
        [HttpGet]
        public async Task<ActionResult<List<ItemData>>> GetItems()
        {
            var items = await context.Items.ToListAsync();
            return Ok(items);
        }

        [HttpPost]
        public async Task<ActionResult<ItemData>> AddItem(ItemData item)
        {
            if(ModelState.IsValid)
            {
                context.Items.Add(item);
                await context.SaveChangesAsync();
                return CreatedAtAction("GetItem", new { item.Id }, item);
            }

            return new JsonResult("server error") { StatusCode = 500 };
        }

        [MapToApiVersion(1)]
        [HttpGet("{id}")]
        public async Task<ActionResult<ItemData>> GetItem(int id)
        {
            var item = await context.Items.FindAsync(id);
            if (item == null)
            {
                return NotFound();
            }
            return Ok(item);
        }

        [HttpPut("{id}")]
        public async Task<ActionResult> UdateItem(int id, ItemData toUpdate)
        {
            if (id != toUpdate.Id)
            {
                return BadRequest();
            }

            var item = await context.Items.FindAsync(toUpdate.Id);
            if (item == null)
            {
                return NotFound();
            }

            item.Title = toUpdate.Title;
            item.Description = toUpdate.Description;
            item.Done = toUpdate.Done;

            await context.SaveChangesAsync();

            return NoContent();
        }

        [HttpDelete("{id}")]
        public async Task<ActionResult<ItemData>> DeleteItem(int id)
        {
            var item = await context.Items.FindAsync(id);
            if (item == null)
            {
                return NotFound();
            }

            context.Items.Remove(item);
            await context.SaveChangesAsync();

            return Ok(item);
        }
    }
}
